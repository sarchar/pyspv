
class Script:
    def __init__(self, program=b''):
        self.program = program

    def serialize(self):
        return self.program

