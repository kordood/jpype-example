class parent:

    def __init__(self, num, level):
        self.num = num
        self.level = level
        self.dummy = dummy()


class child:

    def __init__(self, parent):
        self.parent = parent
        copy_member(self, parent)


class dummy:

    def __init__(self):
        self.const = "OGOHO"


def copy_member(src, dest):
    for key, value in src.__dict__.items():
        dest.__setattr__(key, value)

if __name__ == '__main__':
    p = parent(1, 2)
    c = child(p)
    copy_member(p, c)
    print(c)