from urllib.parse               import parse_qs

from modules.tg_miniapp_auth    import validate_init_data, NotAuthorized


bot_id              = 1234567890
init_data_string    = "user=%7B%..."


if __name__ == "__main__":
    init_data = parse_qs(init_data_string, keep_blank_values = True)

    try:
        validate_init_data(init_data, bot_id)
        print('Authorized')
    except NotAuthorized as e:
        print('Not authorized: ' + str(e))
