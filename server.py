"""
MiniMessenger demo server.

Функції сервера:
- зберігає акаунти в accounts.json (user, пароль, телефон, display_name, pq_pub);
- приймає перше повідомлення від клієнта: signup/login;
- тримає мапу online-клієнтів (user -> writer);
- маршрутизує службові та зашифровані повідомлення між клієнтами:
    * ratchet_pub / dr_init / msg  – для Double Ratchet;
    * pq_init                      – для PQ-KEM;
- реалізує простий механізм інвайтів (/invite, /invites, /accept);
- віддає профілі (/get_profile) та PQ-публічні ключі (/get_pq_pub).
"""

import asyncio
import json
import hashlib
import os
from typing import Dict, Set

ACCOUNTS_FILE = "accounts.json"

# online-клієнти: user -> writer (активне TCP-зʼєднання)
clients: Dict[str, asyncio.StreamWriter] = {}

# акаунти: user -> dict(password_hash, phone, display_name, pq_pub, ...)
accounts: Dict[str, Dict[str, str]] = {}

# pending_invites: для кожного користувача множина тих, хто його запросив у чат
pending_invites: Dict[str, Set[str]] = {}


# ---------------------------------------------------------------------------
# Робота з файлами акаунтів
# ---------------------------------------------------------------------------

def load_accounts() -> None:
    """Завантажити accounts.json у глобальний словник accounts."""
    global accounts
    if os.path.exists(ACCOUNTS_FILE):
        try:
            with open(ACCOUNTS_FILE, "r", encoding="utf-8") as f:
                accounts = json.load(f)
        except Exception:
            # Якщо файл зламаний / не читається – стартуємо з порожньої бази
            accounts = {}
    else:
        accounts = {}


def save_accounts() -> None:
    """Зберегти поточний стан accounts у accounts.json."""
    with open(ACCOUNTS_FILE, "w", encoding="utf-8") as f:
        json.dump(accounts, f, ensure_ascii=False, indent=2)


def hash_password(password: str) -> str:
    """
    Спрощений хеш пароля.

    У реальному житті тут має бути PBKDF2/Argon2 + сіль.
    Тут – SHA-256 з префіксом для демо.
    """
    return hashlib.sha256(("MiniMessenger:" + password).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Обробка одного клієнта
# ---------------------------------------------------------------------------

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """
    Основний цикл обробки клієнта.

    1) Читає перше повідомлення: signup / login.
    2) Аутентифікує користувача, додає в clients.
    3) У циклі читає наступні JSON-пакети й обробляє:
       - раутинг зашифрованих повідомлень (ratchet_pub, dr_init, msg, pq_init);
       - роботу з профілями та PQ-публічними ключами;
       - інвайти (invite, list_invites, accept_invite).
    """
    addr = writer.get_extra_info("peername")
    print(f"[server] New connection from {addr}")
    username = None

    try:
        # 1) Перше повідомлення: signup або login
        line = await reader.readline()
        if not line:
            writer.close()
            await writer.wait_closed()
            return

        try:
            first = json.loads(line.decode("utf-8").strip())
        except json.JSONDecodeError:
            writer.close()
            await writer.wait_closed()
            return

        msg_type = first.get("type")
        user = first.get("user")
        password = first.get("password")
        phone = first.get("phone")  # для signup
        display_name = first.get("display_name") or user
        pq_pub = first.get("pq_pub")  # для signup, публічний PQ-KEM ключ

        if not isinstance(user, str) or not isinstance(password, str):
            err = {"type": "error", "error": "user and password required"}
            writer.write((json.dumps(err) + "\n").encode("utf-8"))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        # ---------------- SIGNUP ----------------
        if msg_type == "signup":
            if user in accounts:
                err = {"type": "error", "error": f"user '{user}' already exists"}
                writer.write((json.dumps(err) + "\n").encode("utf-8"))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            if not phone:
                err = {"type": "error", "error": "phone is required for signup"}
                writer.write((json.dumps(err) + "\n").encode("utf-8"))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            if not pq_pub:
                err = {
                    "type": "error",
                    "error": "pq_pub is required for signup (PQ-KEM public key)",
                }
                writer.write((json.dumps(err) + "\n").encode("utf-8"))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            accounts[user] = {
                "password_hash": hash_password(password),
                "phone": phone,
                "display_name": display_name,
                "pq_pub": pq_pub,
            }
            save_accounts()

            username = user
            clients[username] = writer
            print(f"[server] New account created and logged in: {username}")

            ok = {"type": "signup_ok", "user": username}
            writer.write((json.dumps(ok) + "\n").encode("utf-8"))
            await writer.drain()

        # ---------------- LOGIN ----------------
        elif msg_type == "login":
            if user not in accounts:
                err = {"type": "error", "error": f"user '{user}' does not exist"}
                writer.write((json.dumps(err) + "\n").encode("utf-8"))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            if accounts[user].get("password_hash") != hash_password(password):
                err = {"type": "error", "error": "invalid password"}
                writer.write((json.dumps(err) + "\n").encode("utf-8"))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            # Проста захист від подвійного логіну того самого користувача
            if user in clients and clients[user] is not writer:
                err = {
                    "type": "error",
                    "error": f"user '{user}' already logged in from another client",
                }
                writer.write((json.dumps(err) + "\n").encode("utf-8"))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            username = user
            clients[username] = writer
            print(f"[server] User logged in: {username}")

            ok = {"type": "login_ok", "user": username}
            writer.write((json.dumps(ok) + "\n").encode("utf-8"))
            await writer.drain()

        # ---------------- Некоректний перший пакет ----------------
        else:
            err = {"type": "error", "error": "first message must be 'signup' or 'login'"}
            writer.write((json.dumps(err) + "\n").encode("utf-8"))
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            return

        # ------------------------------------------------------------------
        # 2) Основний цикл: роутинг повідомлень та сервісні операції
        # ------------------------------------------------------------------
        while True:
            line = await reader.readline()
            if not line:
                break  # клієнт відключився

            try:
                env = json.loads(line.decode("utf-8").strip())
            except json.JSONDecodeError:
                continue

            mtype = env.get("type")

            # --- Прямий роутинг між клієнтами: рачети, PQ-KEM та повідомлення ---
            if mtype in ("ratchet_pub", "dr_init", "msg", "pq_init"):
                to_user = env.get("to")
                if not to_user:
                    continue

                dest_writer = clients.get(to_user)
                if dest_writer is None:
                    # Адресат не онлайн
                    err = {"type": "error", "error": f"user '{to_user}' not online"}
                    writer.write((json.dumps(err) + "\n").encode("utf-8"))
                    await writer.drain()
                    continue

                # Додаємо поле "from" і просто пересилаємо пакет
                env["from"] = username
                dest_writer.write((json.dumps(env) + "\n").encode("utf-8"))
                await dest_writer.drain()

            # --- Профілі ---
            elif mtype == "get_profile":
                # Якщо user не вказаний – віддаємо власний профіль
                target_user = env.get("user") or username
                acc = accounts.get(target_user)

                if not acc:
                    resp = {"type": "error", "error": f"user '{target_user}' not found"}
                else:
                    resp = {
                        "type": "profile",
                        "user": target_user,
                        "phone": acc.get("phone"),
                        "display_name": acc.get("display_name") or target_user,
                    }

                writer.write((json.dumps(resp) + "\n").encode("utf-8"))
                await writer.drain()

            # --- Отримати PQ-публічний ключ іншого користувача ---
            elif mtype == "get_pq_pub":
                target_user = env.get("user")
                acc = accounts.get(target_user)

                if not acc or "pq_pub" not in acc:
                    resp = {"type": "error", "error": f"no pq_pub for user '{target_user}'"}
                else:
                    resp = {
                        "type": "pq_pub",
                        "user": target_user,
                        "pq_pub": acc["pq_pub"],
                    }

                writer.write((json.dumps(resp) + "\n").encode("utf-8"))
                await writer.drain()

            # --- Відправка інвайту ---
            elif mtype == "invite":
                to_user = env.get("to")
                if not to_user or to_user not in accounts:
                    resp = {"type": "error", "error": f"user '{to_user}' not found"}
                else:
                    inv_set = pending_invites.setdefault(to_user, set())
                    inv_set.add(username)
                    resp = {"type": "invite_sent", "to": to_user}

                writer.write((json.dumps(resp) + "\n").encode("utf-8"))
                await writer.drain()

            # --- Список інвайтів ---
            elif mtype == "list_invites":
                inv = sorted(pending_invites.get(username, set()))
                resp = {"type": "invites", "items": inv}
                writer.write((json.dumps(resp) + "\n").encode("utf-8"))
                await writer.drain()

            # --- Прийняти інвайт ---
            elif mtype == "accept_invite":
                inviter = env.get("inviter")
                inv_set = pending_invites.get(username, set())

                if not inviter:
                    resp = {"type": "error", "error": "inviter is required"}
                elif inviter not in inv_set:
                    resp = {"type": "error", "error": f"no invite from '{inviter}'"}
                else:
                    # Видаляємо інвайт із черги
                    inv_set.remove(inviter)
                    if not inv_set:
                        pending_invites.pop(username, None)
                    else:
                        pending_invites[username] = inv_set

                    resp = {
                        "type": "invite_accepted",
                        "inviter": inviter,
                        "by": username,
                    }

                writer.write((json.dumps(resp) + "\n").encode("utf-8"))
                await writer.drain()

            else:
                # Місце для майбутніх типів (наприклад, статус, presence, тощо)
                pass

    finally:
        # При будь-якому виході з handle_client – чистимо ресурси
        if username:
            print(f"[server] {username} disconnected")
            if clients.get(username) is writer:
                del clients[username]

        writer.close()
        await writer.wait_closed()


# ---------------------------------------------------------------------------
# Точка входу сервера
# ---------------------------------------------------------------------------

async def main() -> None:
    """Запустити TCP-сервер MiniMessenger на порту 9999."""
    load_accounts()
    server = await asyncio.start_server(handle_client, "0.0.0.0", 9999)
    addrs = ", ".join(str(sock.getsockname()) for sock in server.sockets)
    print(f"[server] Listening on {addrs}")
    print(f"[server] Loaded accounts: {list(accounts.keys())}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
