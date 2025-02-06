import typing
import time
import base64

from urllib.parse       import unquote

from nacl.signing       import VerifyKey
from nacl.exceptions    import BadSignatureError


# Telegram Public Keys
PUBLIC_KEYS = {
    'production':   bytes.fromhex('e7bf03a2fa4602af4580703d88dda5bb59f32ed8b02a56c187fe7d34caed242d'),
    'test':         bytes.fromhex('40055058a4ee38156a06562e52eece92a771bcd8346a8c4615cb7376eddf72ec')
}


class NotAuthorized(Exception):
    pass


def init_data_to_string(init_data: dict, bot_id: int):
    check_string = "\n" . join(f"{key}={unquote(value[0])}"
        for key, value in sorted(init_data.items()))

    return f"{bot_id}:WebAppData\n{check_string}".encode()


def validate_init_data(
        init_data:      dict[typing.AnyStr, list[typing.AnyStr]],
        bot_id:         int,
        expires_in:     int = 3600,
        environment:    str = 'production',
):
    auth_date_string = init_data.get('auth_date', [ None ])[0]
    if not auth_date_string or not auth_date_string.isdigit():
        raise NotAuthorized('No auth_date in initData')

    if int(time.time()) - int(auth_date_string) > expires_in:
        raise NotAuthorized('initData auth_time expired')

    # Get and remove signature from initData
    signature = init_data.pop('signature', [ None ])[0]
    if not signature:
        raise NotAuthorized('No signature in initData')

    # remove hash from initData
    init_data.pop('hash', None)

    verify_key          = VerifyKey(PUBLIC_KEYS[environment])
    init_data_string    = init_data_to_string(init_data, bot_id)
    signature           += '=' * ((4 - len(signature) % 4) % 4) # base64 padding
    signature_bytes     = base64.urlsafe_b64decode(signature)

    try:
        verify_key.verify(init_data_string, signature_bytes)
    except BadSignatureError:
        raise NotAuthorized('initData signature is not valid')
