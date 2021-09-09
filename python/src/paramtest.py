class ReferencableBool:

    def __init__(self, bool):
        self.bool = bool


def iamfunction(rb):
    rb.bool = False


if __name__ == '__main__':
    boooool = ReferencableBool(True)
    print(boooool.bool)
    iamfunction(boooool)
    print(boooool.bool)
