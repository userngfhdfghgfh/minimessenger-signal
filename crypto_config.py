from __future__ import annotations

from typing import Any, Dict, Tuple
import hashlib

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric.x448 import X448PrivateKey, X448PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from doubleratchet import DoubleRatchet as DR, EncryptedMessage, Header
from doubleratchet.recommended import (
    aead_aes_hmac,
    diffie_hellman_ratchet_curve448 as dhr448,
    HashFunction,
    kdf_hkdf,
    kdf_separate_hmacs,
)

# ============================================================================
#  Double Ratchet конфіг для MiniMessenger
# ============================================================================


class ChatDoubleRatchet(DR):
    """
    Обгортка над базовим DoubleRatchet.

    Ми перевизначаємо тільки _build_associated_data, щоб чітко контролювати
    формат AD (associated data), який потім йде в AEAD.
    """

    @staticmethod
    def _build_associated_data(ad: bytes, header: Header) -> bytes:
        """
        Формуємо "повне" AD таким чином:

            AD_base || ratchet_pub || sending_chain_length || previous_sending_chain_length

        де:
          * AD_base            – те, що повертає make_associated_data(...)
          * ratchet_pub        – публічний ключ поточного DH-рачета
          * sending_chain_*    – лічильники повідомлень у ланцюжках

        Це привʼязує шифротекст до конкретного стану рачета.
        """
        return (
            ad
            + header.ratchet_pub
            + header.sending_chain_length.to_bytes(8, "big")
            + header.previous_sending_chain_length.to_bytes(8, "big")
        )


class ChatDiffieHellmanRatchet(dhr448.DiffieHellmanRatchet):
    """
    Використовуємо рекомендований DH-рачeт на X448.

    Це «класичний» еліптичний Diffie–Hellman, не пост-квантовий.
    """


class ChatAEAD(aead_aes_hmac.AEAD):
    """
    AEAD: AES для шифрування + HMAC-SHA-512 для MAC.

    Параметри беруться з recommended.aead_aes_hmac, але ми вказуємо свій
    контекст (_get_info) і явний HashFunction.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return b"MiniMessenger AEAD"


class ChatRootChainKDF(kdf_hkdf.KDF):
    """
    HKDF(SHA-512) для root-ланцюжка.

    З root-ключа й DH-результату породжуємо новий root-ключ + ключ
    для message-chain.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512

    @staticmethod
    def _get_info() -> bytes:
        return b"MiniMessenger RootChain"


class ChatMessageChainKDF(kdf_separate_hmacs.KDF):
    """
    Відокремлена KDF для message-ланцюжка.

    Використовує урізаний SHA-512_256 для HMAC, що дає 256-бітні ключі
    для шифрування окремих повідомлень.
    """

    @staticmethod
    def _get_hash_function() -> HashFunction:
        return HashFunction.SHA_512_256


DR_CONFIG: Dict[str, Any] = {
    "diffie_hellman_ratchet_class": ChatDiffieHellmanRatchet,
    "root_chain_kdf": ChatRootChainKDF,
    "message_chain_kdf": ChatMessageChainKDF,
    "message_chain_constant": b"\x01\x02",
    "dos_protection_threshold": 100,
    "max_num_skipped_message_keys": 1000,
    "aead": ChatAEAD,
}


def make_associated_data(our_id: str, peer_id: str) -> bytes:
    """
    Базове AD для сесії: "MiniMessenger:alice|bob".

    Імена сортуються лексикографічно, щоб і Alice, і Bob отримали
    однаковий рядок (симетричність).
    """
    pair = "|".join(sorted([our_id, peer_id]))
    return f"MiniMessenger:{pair}".encode("utf-8")


def make_shared_secret_from_passphrase(passphrase: str) -> bytes:
    """
    Створити 32-байтовий секрет із passphrase через SHA-256.

    У «реальному житті» на це місце краще ставити PBKDF2/Argon2 + соль.
    У цьому варіанті ми цю функцію майже не використовуємо, але залишаємо
    для сумісності зі старими експериментами.
    """
    return hashlib.sha256(("MiniMessenger:" + passphrase).encode("utf-8")).digest()


def generate_ratchet_keypair() -> Tuple[bytes, bytes]:
    """
    Згенерувати X448-ключі для DH-рачета Double Ratchet.

    Повертає:
      priv_raw – 56 байт приватного ключа (Raw)
      pub_raw  – 56 байт публічного ключа (Raw)
    """
    priv_obj = X448PrivateKey.generate()

    priv_raw = priv_obj.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pub_raw = priv_obj.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_raw, pub_raw


# ============================================================================
#  «Пост-квантовий» KEM-шар (зараз – заглушка на X448)
# ============================================================================

def pq_kem_keygen() -> Tuple[bytes, bytes]:
    """
    Згенерувати пару ключів для KEM-рівня акаунта.

    ЗАРАЗ:
      * використовується X448 (класичний EC-DH, НЕ стійкий до квантових атак);
      * API вже відповідає типу "пост-квантового" KEM:
          -> (public_key, private_key) у Raw форматі.

    Надалі X448 легко замінити на справжній PQ-KEM (Kyber і т.п.),
    не змінюючи код клієнта/сервера.
    """
    priv = X448PrivateKey.generate()

    priv_raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )

    pub_raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    return pub_raw, priv_raw


def _pq_kem_kdf(shared: bytes) -> bytes:
    """
    Внутрішня KDF для перетворення DH-результату на 32-байтовий shared_secret.

    Використовуємо HKDF(SHA-512) без солі, з info = "MiniMessenger PQ-KEM".
    При заміні на справжній PQ-KEM цю функцію можна залишити як є.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=None,
        info=b"MiniMessenger PQ-KEM",
    )
    return hkdf.derive(shared)


def pq_kem_encapsulate(peer_pub_raw: bytes) -> Tuple[bytes, bytes]:
    """
    KEM-encapsulate (ініціатор):

      1. Відновлюємо X448-публічний ключ peer з байтів.
      2. Генеруємо епфемерну X448-пару (eph_priv, eph_pub).
      3. Рахуємо DH(eph_priv, peer_pub).
      4. Проганяємо через _pq_kem_kdf -> shared_secret (32 байти).
      5. Повертаємо:
           ct           – шифротекст для peer (тут це просто eph_pub_raw),
           shared_secret – спільний ключ KEM-рівня.

    У реальному PQ-KEM замість X448 була б Kyber-ciphertext.
    """
    peer_pub = X448PublicKey.from_public_bytes(peer_pub_raw)

    # Епфемерний приватний ключ ініціатора
    eph_priv = X448PrivateKey.generate()
    eph_pub_raw = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    # DH(eph_priv, peer_pub) -> shared
    shared = eph_priv.exchange(peer_pub)
    shared_secret = _pq_kem_kdf(shared)

    ct = eph_pub_raw
    return ct, shared_secret


def pq_kem_decapsulate(own_priv_raw: bytes, ct: bytes) -> bytes:
    """
    KEM-decapsulate (респондера):

      1. own_priv_raw  – приватний KEM-ключ акаунта (Raw X448).
      2. ct            – те, що нам надіслав ініціатор (eph_pub_raw).
      3. Обчислюємо DH(own_priv, eph_pub).
      4. Пропускаємо через _pq_kem_kdf -> shared_secret.

    Якщо KEM буде замінений на справжній PQ, сигнатура функції може
    залишитись такою ж (own_priv_raw + ct -> shared_secret).
    """
    own_priv = X448PrivateKey.from_private_bytes(own_priv_raw)
    eph_pub = X448PublicKey.from_public_bytes(ct)

    shared = own_priv.exchange(eph_pub)
    shared_secret = _pq_kem_kdf(shared)

    return shared_secret
