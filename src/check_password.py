def check_password(passwd):
    val = True
    err_text = None

    if len(passwd) < 8:
        err_text = 'Password length should be at least 8'
        val = False

    if not any(char.isdigit() for char in passwd):
        err_text = 'Password should have at least one numeral'
        val = False

    if not any(char.isupper() for char in passwd):
        err_text = 'Password should have at least one uppercase letter'
        val = False

    if not any(char.islower() for char in passwd):
        err_text = 'Password should have at least one lowercase letter'
        val = False

    return val, err_text
