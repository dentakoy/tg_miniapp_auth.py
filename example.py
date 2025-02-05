from modules.tg_miniapp_auth import validate_init_data


bot_id      = "1234567890"
init_data   = "user=%7B..."


if __name__ == "__main__":
    is_valid = validate_init_data(init_data, bot_id)

    if is_valid:
        print("Authorized")
    else:
        print("Not authorized")
