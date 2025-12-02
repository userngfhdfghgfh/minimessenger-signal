"""
MiniMessenger CLI client.

Тестовий CLI-клієнт, який демонструє:
- реєстрацію/логін користувачів на TCP-сервері;
- зберігання профілю (ім'я, телефон, PQ-публічний ключ);
- встановлення end-to-end сесії через:
    1) пост-квантовий KEM (pq_kem_*) для отримання спільного секрету;
    2) Double Ratchet (ChatDoubleRatchet) поверх цього секрету;
- обмін зашифрованими повідомленнями в чаті;
- збереження стану рачета в локальні JSON-файли.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import getpass
import json
import os
from dataclasses import dataclass
from typing import Dict, Optional

from doubleratchet import EncryptedMessage, Header, AuthenticationFailedException
from crypto_config import (
    ChatDoubleRatchet,
    DR_CONFIG,
    make_associated_data,
    generate_ratchet_keypair,
    pq_kem_keygen,
    pq_kem_encapsulate,
    pq_kem_decapsulate,
)


# ---------------------------------------------------------------------------
# Базовий опис активного з'єднання з сервером
# ---------------------------------------------------------------------------


@dataclass
class Connection:
    """Обгортка над (reader, writer) + дані про поточного користувача."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    user: str
    display_name: Optional[str] = None
    phone: Optional[str] = None
    host: str = "127.0.0.1"
    port: int = 9999


# ---------------------------------------------------------------------------
# Конфіг та зберігання PQ-ключів клієнта
# ---------------------------------------------------------------------------

CONFIG_FILE = "client_config.json"
PQ_KEYS_DIR = "pq_client_keys"


def pq_priv_path(user: str) -> str:
    """Шлях до файлу з PQ-приватним ключем конкретного користувача."""
    safe = user.replace("/", "_")
    return os.path.join(PQ_KEYS_DIR, f"{safe}.bin")


def save_pq_priv(user: str, priv_raw: bytes) -> None:
    """Зберегти PQ-приватний ключ у файл (локально на клієнті)."""
    try:
        os.makedirs(PQ_KEYS_DIR, exist_ok=True)
        with open(pq_priv_path(user), "wb") as f:
            f.write(priv_raw)
    except Exception as exc:
        print(f"[system] Failed to save PQ private key for {user}: {exc}")


def load_pq_priv(user: str) -> Optional[bytes]:
    """Завантажити PQ-приватний ключ користувача, якщо файл існує."""
    path = pq_priv_path(user)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception as exc:
        print(f"[system] Failed to load PQ private key for {user}: {exc}")
        return None


def load_client_config() -> dict:
    """
    Завантажити client_config.json, якщо він є.
    Якщо немає або файл зламаний – повернути дефолтні значення host/port.
    """
    cfg = {"host": "127.0.0.1", "port": 9999}

    if not os.path.exists(CONFIG_FILE):
        return cfg

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            if "host" in data:
                cfg["host"] = str(data["host"])
            if "port" in data:
                cfg["port"] = int(data["port"])
    except Exception as exc:
        print(f"[system] Failed to load {CONFIG_FILE}: {exc}")

    return cfg


# ---------------------------------------------------------------------------
# Стан Double Ratchet для конкретного чату (user <-> peer)
# ---------------------------------------------------------------------------


def state_path_for_chat(user: str, peer: str) -> str:
    """
    Шлях до файлу стану Double Ratchet для пари (user, peer).

    Для кожної пари логінів маємо окремий state_...json.
    """
    safe_user = user.replace("/", "_")
    safe_peer = peer.replace("/", "_")
    return f"state_{safe_user}_{safe_peer}.json"


def save_dr_state(dr: ChatDoubleRatchet, path: str) -> None:
    """Зберегти поточний стан Double Ratchet у JSON-файл."""
    try:
        data = dr.json
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
    except Exception as exc:
        print(f"[system] Failed to save DR state: {exc}")


def load_dr_state(path: str) -> Optional[ChatDoubleRatchet]:
    """
    Завантажити стан Double Ratchet з JSON-файлу.

    Повертає ChatDoubleRatchet або None, якщо файлу немає / він зламаний.
    """
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        dr = ChatDoubleRatchet.from_json(data, **DR_CONFIG)
        print(f"[system] Loaded DoubleRatchet state from {path}")
        return dr
    except Exception as exc:
        print(f"[system] Failed to load DR state from {path}: {exc}")
        return None


# ---------------------------------------------------------------------------
# Серіалізація / десеріалізація зашифрованих повідомлень DR
# ---------------------------------------------------------------------------


def encrypted_message_to_dict(msg: EncryptedMessage) -> dict:
    """Перетворити EncryptedMessage на JSON-сумісний словник."""
    return {
        "header": {
            "ratchet_pub": base64.b64encode(msg.header.ratchet_pub).decode("ascii"),
            "previous_sending_chain_length": msg.header.previous_sending_chain_length,
            "sending_chain_length": msg.header.sending_chain_length,
        },
        "ciphertext": base64.b64encode(msg.ciphertext).decode("ascii"),
    }


def encrypted_message_from_dict(d: dict) -> EncryptedMessage:
    """Відновити EncryptedMessage зі словника (header + ciphertext)."""
    header_data = d["header"]
    header = Header(
        ratchet_pub=base64.b64decode(header_data["ratchet_pub"]),
        previous_sending_chain_length=int(
            header_data["previous_sending_chain_length"]
        ),
        sending_chain_length=int(header_data["sending_chain_length"]),
    )
    ciphertext = base64.b64decode(d["ciphertext"])
    return EncryptedMessage(header=header, ciphertext=ciphertext)


# ---------------------------------------------------------------------------
# Double Ratchet handshake (поверх уже готового shared_secret)
# ---------------------------------------------------------------------------


async def handshake_responder(
    conn: Connection,
    peer: str,
    shared_secret: bytes,
    ad: bytes,
) -> ChatDoubleRatchet:
    """
    Роль responder:
    - генерує власну X448-пару (ratchet keypair),
    - шле свій ratchet_pub peer'у,
    - чекає dr_init з зашифрованим першим повідомленням,
    - ініціалізує DoubleRatchet.decrypt_initial_message().
    """
    reader, writer = conn.reader, conn.writer
    priv_raw, pub_raw = generate_ratchet_keypair()

    ratchet_msg = {
        "type": "ratchet_pub",
        "to": peer,
        "ratchet_pub": base64.b64encode(pub_raw).decode("ascii"),
    }
    writer.write((json.dumps(ratchet_msg) + "\n").encode("utf-8"))
    await writer.drain()
    print("[system] Sent ratchet public key, waiting for initial DR message...")

    while True:
        line = await reader.readline()
        if not line:
            raise RuntimeError("Connection closed during handshake (responder)")

        env = json.loads(line.decode("utf-8").strip())
        msg_type = env.get("type")

        if msg_type == "dr_init" and env.get("from") == peer:
            payload = env["payload"]
            encrypted = encrypted_message_from_dict(payload)

            dr, plaintext = await ChatDoubleRatchet.decrypt_initial_message(
                shared_secret=shared_secret,
                own_ratchet_priv=priv_raw,
                message=encrypted,
                associated_data=ad,
                **DR_CONFIG,
            )
            text = plaintext.decode("utf-8", errors="replace")
            print(
                f"[system] Handshake complete. "
                f"Initial message from {env.get('from')}: {text}"
            )
            return dr

        elif msg_type in ("error", "info"):
            print(f"[system] (handshake) {env}")
        else:
            # все інше ігноруємо під час handshake
            continue


async def handshake_initiator(
    conn: Connection,
    peer: str,
    shared_secret: bytes,
    ad: bytes,
) -> ChatDoubleRatchet:
    """
    Роль initiator:
    - чекає, поки peer надішле ratchet_pub,
    - шифрує перше повідомлення через encrypt_initial_message(),
    - шле dr_init з EncryptedMessage всередині.
    """
    reader, writer = conn.reader, conn.writer
    print("[system] Waiting for peer ratchet public key...")

    ratchet_pub_raw: Optional[bytes] = None
    while ratchet_pub_raw is None:
        line = await reader.readline()
        if not line:
            raise RuntimeError("Connection closed during handshake (initiator)")

        env = json.loads(line.decode("utf-8").strip())
        msg_type = env.get("type")

        if msg_type == "ratchet_pub" and env.get("from") == peer:
            ratchet_pub_raw = base64.b64decode(env["ratchet_pub"])
        elif msg_type in ("error", "info"):
            print(f"[system] (handshake) {env}")
        else:
            continue

    # Перше службове повідомлення всередині DR (можна змінити текст за бажанням)
    initial_text = "(initial DoubleRatchet message)".encode("utf-8")

    dr, encrypted = await ChatDoubleRatchet.encrypt_initial_message(
        shared_secret=shared_secret,
        recipient_ratchet_pub=ratchet_pub_raw,
        message=initial_text,
        associated_data=ad,
        **DR_CONFIG,
    )

    env = {
        "type": "dr_init",
        "to": peer,
        "payload": encrypted_message_to_dict(encrypted),
    }
    writer.write((json.dumps(env) + "\n").encode("utf-8"))
    await writer.drain()
    print("[system] Sent initial DoubleRatchet message, chat is ready.")
    return dr


# ---------------------------------------------------------------------------
# Цикли чату: прийом / передача
# ---------------------------------------------------------------------------


async def chat_recv_loop(
    conn: Connection,
    dr: ChatDoubleRatchet,
    ad: bytes,
    peer: str,
    state_path: str,
) -> None:
    """
    Цикл читання з сокета:
    - приймає JSON-повідомлення від сервера,
    - відфільтровує msg від конкретного peer,
    - дешифрує via dr.decrypt_message(),
    - оновлює та зберігає стан рачета.
    """
    reader = conn.reader
    while True:
        line = await reader.readline()
        if not line:
            print("\n[system] Server closed the connection.")
            return

        try:
            env = json.loads(line.decode("utf-8").strip())
        except json.JSONDecodeError:
            continue

        msg_type = env.get("type")

        if msg_type == "msg" and env.get("from") == peer:
            encrypted = encrypted_message_from_dict(env["payload"])
            try:
                plaintext = await dr.decrypt_message(encrypted, ad)
            except Exception as exc:
                # Бібліотека може викинути помилку "already decrypted before"
                # при повторній спробі дешифрувати той самий пакет (replay).
                if "already decrypted before" in str(exc):
                    # replay / дубль – просто ігноруємо
                    continue
                text = f"<decryption failed: {exc}>"
            else:
                # Успішна дешифрація → оновлюємо локальний DR-стан
                save_dr_state(dr, state_path)
                text = plaintext.decode("utf-8", errors="replace")

            print(f"\n[{peer}] {text}")

        elif msg_type == "error":
            print(f"\n[server error] {env.get('error')}")
        elif msg_type == "info":
            print(f"\n[server info] {env.get('info')}")
        elif msg_type == "profile":
            print(
                f"\n[profile] user={env.get('user')}, "
                f"display_name={env.get('display_name')}, "
                f"phone={env.get('phone')}"
            )
        else:
            # інші службові повідомлення для цього простого боксу ігноруємо
            continue


async def chat_send_loop(
    conn: Connection,
    dr: ChatDoubleRatchet,
    ad: bytes,
    peer: str,
    state_path: str,
) -> None:
    """
    Цикл введення користувача:
    - читає рядки з консолі,
    - обробляє /help, /profile, /leave,
    - інші рядки шифрує через dr.encrypt_message() і шле peer'у.
    """
    writer = conn.writer
    loop = asyncio.get_running_loop()
    print("[system] Entering chat. Type /leave to go back to main menu. /help for commands.")

    while True:
        try:
            # input() без префіксу (щоб не заважати виводу вхідних повідомлень)
            text: str = await loop.run_in_executor(None, input, "")
        except EOFError:
            text = "/leave"

        cmd = text.strip()
        if not cmd:
            continue

        if cmd.lower() in ("/leave", "/exit"):
            print("[system] Leaving chat...")
            return

        if cmd.lower() in ("/help", "/h"):
            print("Chat commands:")
            print("  /help               - show this help")
            print("  /profile            - show your profile (from server)")
            print("  /profile USER       - show profile of USER")
            print("  /leave              - leave chat and go back to main menu")
            print("  any other text      - send encrypted message to peer")
            continue

        if cmd.lower().startswith("/profile"):
            parts = cmd.split(maxsplit=1)
            if len(parts) == 1:
                env = {"type": "get_profile"}
            else:
                env = {"type": "get_profile", "user": parts[1]}
            writer.write((json.dumps(env) + "\n").encode("utf-8"))
            await writer.drain()
            continue

        # Звичайне повідомлення → шифруємо та відправляємо
        encrypted = await dr.encrypt_message(text.encode("utf-8"), ad)
        save_dr_state(dr, state_path)
        payload = encrypted_message_to_dict(encrypted)
        env = {"type": "msg", "to": peer, "payload": payload}
        writer.write((json.dumps(env) + "\n").encode("utf-8"))
        await writer.drain()


# ---------------------------------------------------------------------------
# Відкриття/створення чату (PQ KEM + Double Ratchet)
# ---------------------------------------------------------------------------


async def open_chat(conn: Connection, peer: str, role_hint: Optional[str] = None) -> None:
    """
    Підготувати/відновити DR-сесію з peer і запустити чат.

    Якщо для пари (user, peer) вже є збережений стан рачета – просто відновлюємо.
    Якщо ні – робимо:
      1) PQ-KEM handshake (отримуємо shared_secret),
      2) Double Ratchet handshake (на основі shared_secret),
      3) зберігаємо стан у state_*.json.
    """
    user = conn.user
    state_path = state_path_for_chat(user, peer)
    ad = make_associated_data(user, peer)

    dr = load_dr_state(state_path)
    if dr is None:
        # Новий чат: треба визначити роль + зробити PQ-KEM handshake
        if role_hint in ("initiator", "responder"):
            role = role_hint
        else:
            # Запасний варіант – ручний вибір ролі
            while True:
                role_in = input("Choose role: (i)nitiator or (r)esponder? ").strip().lower()
                if role_in in ("i", "r", "initiator", "responder"):
                    role = "initiator" if role_in.startswith("i") else "responder"
                    break
                print("Please enter 'i' or 'r'.")

        # ---- PQ-KEM handshake: отримати shared_secret ----
        shared_secret: bytes

        if role == "initiator":
            # 1) Попросити у сервера PQ-публічний ключ peer
            req = {"type": "get_pq_pub", "user": peer}
            conn.writer.write((json.dumps(req) + "\n").encode("utf-8"))
            await conn.writer.drain()

            line = await conn.reader.readline()
            if not line:
                print("[system] Connection closed while waiting for pq_pub.")
                return

            resp = json.loads(line.decode("utf-8").strip())
            if resp.get("type") != "pq_pub":
                print(f"[system] Failed to obtain PQ public key of {peer}: {resp}")
                return

            try:
                peer_pq_pub_raw = base64.b64decode(resp["pq_pub"])
            except Exception as exc:
                print(f"[system] Invalid PQ public key for {peer}: {exc}")
                return

            # 2) KEM-encapsulate -> (ct, shared_secret)
            ct, shared_secret = pq_kem_encapsulate(peer_pq_pub_raw)

            # 3) Відправити ct peer'у як окреме службове повідомлення
            pq_msg = {
                "type": "pq_init",
                "to": peer,
                "ct": base64.b64encode(ct).decode("ascii"),
            }
            conn.writer.write((json.dumps(pq_msg) + "\n").encode("utf-8"))
            await conn.writer.drain()

            print("[system] Sent PQ-KEM init to peer, derived shared secret.")

        else:
            # Responder: потрібен локальний PQ-приватний ключ
            my_pq_priv = load_pq_priv(user)
            if my_pq_priv is None:
                print(
                    "[system] No local PQ private key for this account.\n"
                    "  Ви, мабуть, логінилися без signup на цій машині.\n"
                    "  Для приймання чатів (responder) потрібен локальний PQ-ключ."
                )
                return

            print("[system] Waiting for PQ-KEM init from peer...")
            while True:
                line = await conn.reader.readline()
                if not line:
                    print("[system] Connection closed while waiting for PQ-KEM init.")
                    return
                try:
                    env = json.loads(line.decode("utf-8").strip())
                except json.JSONDecodeError:
                    continue

                mtype = env.get("type")
                if mtype == "pq_init" and env.get("from") == peer:
                    try:
                        ct = base64.b64decode(env["ct"])
                    except Exception as exc:
                        print(f"[system] Invalid PQ ciphertext from {peer}: {exc}")
                        return
                    shared_secret = pq_kem_decapsulate(my_pq_priv, ct)
                    print("[system] Received PQ-KEM init, derived shared secret.")
                    break
                elif mtype in ("error", "info"):
                    print(f"[system] (pq) {env}")
                else:
                    # інші типи під час встановлення сесії ігноруємо
                    continue

        # 4) Double Ratchet handshake поверх PQ-секрету
        try:
            if role == "initiator":
                dr = await handshake_initiator(conn, peer, shared_secret, ad)
            else:
                dr = await handshake_responder(conn, peer, shared_secret, ad)
        except AuthenticationFailedException:
            print(
                "[system] Handshake failed: authentication tag mismatch.\n"
                "  → Найчастіше це означає, що щось пішло не так із shared_secret\n"
                "    (PQ-KEM або рачети) або в потоці лишилися старі handshake-повідомлення.\n"
                "    Спробуй ще раз або перезапусти клієнти."
            )
            return
        except Exception as exc:
            print(f"[system] Handshake failed: {exc}")
            return

        save_dr_state(dr, state_path)

    # Запускаємо два таски: прийом та відправка
    recv_task = asyncio.create_task(chat_recv_loop(conn, dr, ad, peer, state_path))
    send_task = asyncio.create_task(chat_send_loop(conn, dr, ad, peer, state_path))

    try:
        done, pending = await asyncio.wait(
            {recv_task, send_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
    finally:
        print("[system] Chat closed, back to main menu.")
        return


# ---------------------------------------------------------------------------
# Підключення до сервера + signup / login
# ---------------------------------------------------------------------------


async def connect_and_auth(host: str, port: int) -> Optional[Connection]:
    """
    Підключитися до сервера, виконати signup або login.

    Повертає Connection або None (якщо щось пішло не так).
    """
    try:
        reader, writer = await asyncio.open_connection(host, port)
    except OSError as exc:
        print(f"[system] Failed to connect to {host}:{port}: {exc}")
        return None

    print(f"[system] Connected to {host}:{port}")

    # Вибір: створити акаунт чи залогінитися
    while True:
        choice = input("Do you want to [s]ign up or [l]ogin? ").strip().lower()
        if choice in ("s", "signup", "l", "login"):
            break
        print("Enter 's' or 'l'.")

    user = input("Username: ").strip()
    password = getpass.getpass("Account password: ")

    if choice.startswith("s"):
        # Реєстрація нового акаунта
        phone = input("Phone (e.g. +380...): ").strip()
        display_name = input("Display name (optional, shown to others): ").strip() or user

        # --- Генеруємо PQ-KEM ключі акаунта ---
        pq_pub_raw, pq_priv_raw = pq_kem_keygen()
        save_pq_priv(user, pq_priv_raw)

        first_msg = {
            "type": "signup",
            "user": user,
            "password": password,
            "phone": phone,
            "display_name": display_name,
            "pq_pub": base64.b64encode(pq_pub_raw).decode("ascii"),
        }
    else:
        # Логін у вже існуючий акаунт
        first_msg = {"type": "login", "user": user, "password": password}
        display_name = None

    writer.write((json.dumps(first_msg) + "\n").encode("utf-8"))
    await writer.drain()

    line = await reader.readline()
    if not line:
        print("[system] Server closed connection during auth.")
        writer.close()
        await writer.wait_closed()
        return None

    resp = json.loads(line.decode("utf-8").strip())
    if resp.get("type") == "error":
        print(f"[system] Auth error: {resp.get('error')}")
        writer.close()
        await writer.wait_closed()
        return None

    if resp.get("type") not in ("signup_ok", "login_ok"):
        print(f"[system] Unexpected auth response: {resp}")
        writer.close()
        await writer.wait_closed()
        return None

    print(f"[system] Auth OK as {resp.get('user')}")

    # Якщо це login – перевіримо, чи є локальний PQ-приватний ключ
    if resp.get("type") == "login_ok":
        if load_pq_priv(user) is None:
            print(
                "[system] WARNING: no local PQ private key for this account.\n"
                "  Ви зможете ініціювати чати (/invite, /chat), але не приймати\n"
                "  нові PQ-чати як responder, поки не відновите ключ (або не зробите новий signup)."
            )

    # Підтягнемо профіль із сервера (display_name, phone)
    profile_display = display_name or user
    profile_phone = None
    try:
        req = {"type": "get_profile"}  # без user -> свій профіль
        writer.write((json.dumps(req) + "\n").encode("utf-8"))
        await writer.drain()

        line2 = await reader.readline()
        if line2:
            prof = json.loads(line2.decode("utf-8").strip())
            if prof.get("type") == "profile":
                profile_display = prof.get("display_name") or profile_display
                profile_phone = prof.get("phone")
            elif prof.get("type") == "error":
                print(f"[system] Could not fetch profile: {prof.get('error')}")
    except Exception as exc:
        print(f"[system] Failed to fetch profile info: {exc}")

    return Connection(
        reader=reader,
        writer=writer,
        user=user,
        display_name=profile_display,
        phone=profile_phone,
        host=host,
        port=port,
    )


# ---------------------------------------------------------------------------
# Допоміжне: список локальних чатів для поточного користувача
# ---------------------------------------------------------------------------


def list_local_chats_for_user(user: str) -> Dict[str, str]:
    """
    Повертає словник:
        peer -> ім'я файлу стану (state_{user}_{peer}.json)
    для всіх чатів, які вже мають локальний DR-стан.
    """
    prefix = f"state_{user}_"
    res: Dict[str, str] = {}
    for fname in os.listdir("."):
        if fname.startswith(prefix) and fname.endswith(".json"):
            peer_part = fname[len(prefix) : -5]  # без префікса та ".json"
            peer = peer_part
            res[peer] = fname
    return res


# ---------------------------------------------------------------------------
# Головне CLI-меню
# ---------------------------------------------------------------------------


async def main() -> None:
    parser = argparse.ArgumentParser(description="Mini DoubleRatchet + PQ-KEM CLI messenger")
    parser.add_argument("--host")  # без дефолта, можна перевизначити з CLI
    parser.add_argument("--port", type=int)
    args = parser.parse_args()

    cfg = load_client_config()
    host = args.host or cfg["host"]
    port = args.port or cfg["port"]

    conn: Optional[Connection] = None

    print("MiniMessenger CLI")
    print("Type /help for commands.")

    loop = asyncio.get_running_loop()

    while True:
        try:
            cmd_line: str = await loop.run_in_executor(None, input, "cli> ")
        except EOFError:
            cmd_line = "/quit"

        cmd = cmd_line.strip()

        if not cmd:
            continue

        # ---------------- Загальні команди ----------------

        if cmd.lower() in ("/quit", "/exit"):
            print("[system] Bye.")
            if conn:
                conn.writer.close()
                try:
                    await conn.writer.wait_closed()
                except Exception:
                    pass
            break

        if cmd.lower() in ("/help", "/h"):
            print("Commands:")
            print("  /connect           - connect to server and login/signup")
            print("  /me                - show current local user & connection status")
            print("  /chats             - list local chats for current user")
            print("  /chat PEER         - open chat with PEER (requires connection)")
            print("  /disconnect        - close current server connection")
            print("  /invite USER       - send chat invite to USER")
            print("  /invites           - list invites you have received")
            print("  /accept USER       - accept invite from USER and open chat")
            print("  /help              - show this help")
            print("  /quit              - exit program")
            continue

        # ---------------- З'єднання з сервером ----------------

        if cmd.lower() == "/connect":
            if conn:
                print(
                    f"[system] Already connected as {conn.user} "
                    f"to {conn.host}:{conn.port}"
                )
                continue
            new_conn = await connect_and_auth(host, port)
            if new_conn:
                conn = new_conn
            continue

        if cmd.lower() == "/disconnect":
            if not conn:
                print("[system] Not connected.")
                continue
            conn.writer.close()
            try:
                await conn.writer.wait_closed()
            except Exception:
                pass
            print("[system] Disconnected from server.")
            conn = None
            continue

        # ---------------- Інформація про себе / локальні чати ----------------

        if cmd.lower() == "/me":
            if not conn:
                print("[system] Not connected to server.")
                continue

            print(f"[system] Connected to {conn.host}:{conn.port}")
            print(f"  user:          {conn.user}")
            print(f"  display_name:  {conn.display_name or conn.user}")
            if conn.phone:
                print(f"  phone:         {conn.phone}")
            else:
                print("  phone:         (not set)")

            chats = list_local_chats_for_user(conn.user)
            if chats:
                print(f"  local_chats:   {', '.join(chats.keys())}")
            else:
                print("  local_chats:   (none)")
            continue

        if cmd.lower() == "/chats":
            if not conn:
                print("[system] Need to /connect first to know which user you are.")
                continue
            chats = list_local_chats_for_user(conn.user)
            if not chats:
                print("[system] No local chats for this user yet.")
            else:
                print("[system] Local chats:")
                for peer, fname in chats.items():
                    print(f"  {peer}  (state file: {fname})")
            continue

        # ---------------- Інвайти ----------------

        if cmd.lower().startswith("/invite "):
            if not conn:
                print("[system] You must /connect first.")
                continue
            parts = cmd.split(maxsplit=1)
            if len(parts) != 2 or not parts[1]:
                print("Usage: /invite USER")
                continue
            to_user = parts[1].strip()
            req = {"type": "invite", "to": to_user}
            conn.writer.write((json.dumps(req) + "\n").encode("utf-8"))
            await conn.writer.drain()

            # Чекаємо службову відповідь від сервера
            while True:
                line = await conn.reader.readline()
                if not line:
                    print("[system] Connection closed while waiting invite response.")
                    conn.writer.close()
                    try:
                        await conn.writer.wait_closed()
                    except Exception:
                        pass
                    conn = None
                    break

                resp = json.loads(line.decode("utf-8").strip())
                rtype = resp.get("type")
                if rtype == "invite_sent":
                    print(f"[system] Invite sent to {resp.get('to')}")
                    break
                elif rtype == "error":
                    print(f"[system] Invite error: {resp.get('error')}")
                    break
                else:
                    # Якщо прилетіло щось асинхронне (msg, pq_init, ...),
                    # просто покажемо й продовжимо чекати відповідь по інвайту.
                    print(f"[system] Ignoring async message while waiting invite: {resp}")
            continue

        if cmd.lower() == "/invites":
            if not conn:
                print("[system] You must /connect first.")
                continue

            req = {"type": "list_invites"}
            conn.writer.write((json.dumps(req) + "\n").encode("utf-8"))
            await conn.writer.drain()

            while True:
                line = await conn.reader.readline()
                if not line:
                    print("[system] Connection closed while waiting invites.")
                    conn.writer.close()
                    try:
                        await conn.writer.wait_closed()
                    except Exception:
                        pass
                    conn = None
                    break

                resp = json.loads(line.decode("utf-8").strip())
                rtype = resp.get("type")

                if rtype == "invites":
                    items = resp.get("items", [])
                    if not items:
                        print("[system] You have no pending invites.")
                    else:
                        print("[system] You have invites from:")
                        for u in items:
                            print(f"  - {u}")
                    break
                elif rtype == "error":
                    print(f"[system] Error: {resp.get('error')}")
                    break
                else:
                    # Наприклад, якщо прилетів msg або pq_init, поки ми чекаємо список інвайтів
                    print(f"[system] Ignoring async message while waiting invites: {resp}")
            continue

        if cmd.lower().startswith("/accept "):
            if not conn:
                print("[system] You must /connect first.")
                continue

            parts = cmd.split(maxsplit=1)
            if len(parts) != 2 or not parts[1]:
                print("Usage: /accept USER")
                continue

            inviter = parts[1].strip()
            req = {"type": "accept_invite", "inviter": inviter}
            conn.writer.write((json.dumps(req) + "\n").encode("utf-8"))
            await conn.writer.drain()

            while True:
                line = await conn.reader.readline()
                if not line:
                    print("[system] Connection closed while waiting accept_invite response.")
                    conn.writer.close()
                    try:
                        await conn.writer.wait_closed()
                    except Exception:
                        pass
                    conn = None
                    break

                resp = json.loads(line.decode("utf-8").strip())
                rtype = resp.get("type")

                if rtype == "invite_accepted":
                    print(f"[system] Invite from {inviter} accepted. Opening chat...")
                    await open_chat(conn, inviter, role_hint="responder")
                    break
                elif rtype == "error":
                    print(f"[system] Cannot accept invite: {resp.get('error')}")
                    break
                else:
                    print(
                        "[system] Ignoring async message while waiting accept_invite: "
                        f"{resp}"
                    )
            continue

        # ---------------- Відкрити чат вручну ----------------

        if cmd.lower().startswith("/chat "):
            if not conn:
                print("[system] You must /connect and login first.")
                continue
            parts = cmd.split(maxsplit=1)
            if len(parts) != 2 or not parts[1]:
                print("Usage: /chat PEER")
                continue
            peer = parts[1].strip()
            print(f"[system] Opening chat with {peer}...")
            await open_chat(conn, peer, role_hint="initiator")
            # Після виходу з чату лишаємося в main-меню, з'єднання живе
            continue

        # ---------------- Невідома команда ----------------

        print("[system] Unknown command. Type /help for list of commands.")


if __name__ == "__main__":
    asyncio.run(main())
