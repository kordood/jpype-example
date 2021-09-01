def copy_member(src, dest):
    for key, value in src.__dict__.items():
        dest.__setattr__(key, value)