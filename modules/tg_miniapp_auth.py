import base64
from urllib.parse import parse_qs, unquote

from nacl.signing       import VerifyKey
from nacl.exceptions    import BadSignatureError


# Telegram Public Keys
PUBLIC_KEYS = {
    "production":   bytes.fromhex("e7bf03a2fa4602af4580703d88dda5bb59f32ed8b02a56c187fe7d34caed242d"),
    "test":         bytes.fromhex("40055058a4ee38156a06562e52eece92a771bcd8346a8c4615cb7376eddf72ec")
}


class NoSignatureInInitData(Exception):
    pass


class NotAuthorized(Exception):
    pass


def validate_init_data( init_data:      str,
                        bot_id:         str,
                        environment:    str     = "production",
                        exception_mode: bool    = False
) -> bool:
    params = parse_qs(init_data, keep_blank_values = True)

    # Extract signature and hash, and clean params
    signature = params.pop("signature", [ None ])[0]
    params.pop("hash", None)

    if not signature:
       raise NoSignatureInInitData

    # Ensure Base64 padding for signature
    signature       += "=" * ((4 - len(signature) % 4) % 4)
    signature_bytes = base64.urlsafe_b64decode(signature)

    # Format key-value pairs
    check_string = "\n" . join(f"{k}={unquote(v[0])}"
        for k, v in sorted(params.items()))

    data_string = f"{bot_id}:WebAppData\n{check_string}"
    verify_key  = VerifyKey(PUBLIC_KEYS[environment])

    try:
        verify_key.verify(data_string.encode(), signature_bytes)
        return True

    except BadSignatureError:
        if exception_mode:
            raise NotAuthorized

        return False
