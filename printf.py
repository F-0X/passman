

class printf():
    def __init__(self):
        self.colours = {'black' : '0',
                        'red' : '1',
                        'green' : '2',
                        'yellow' : '3',
                        'blue' : '4',
                        'purple' : '5',
                        'cyan' : '6',
                        'white' : '7',}

    def red(self, string):
        print('\x1b[0;3'+str(self.colours['red'])+';40m'+string+'\x1b[0m')

    def bright_red(self, string):
        print('\x1b[1;3'+str(self.colours['red'])+';40m'+string+'\x1b[0m')

    def green(self, string):
        print('\x1b[0;3'+str(self.colours['green'])+';40m'+string+'\x1b[0m')

    def bright_green(self, string):
        print('\x1b[1;3'+str(self.colours['green'])+';40m'+string+'\x1b[0m')

    def yellow(self, string):
        print('\x1b[0;3'+str(self.colours['yellow'])+';40m'+string+'\x1b[0m')

    def bright_yellow(self, string):
        print('\x1b[1;3'+str(self.colours['yellow'])+';40m'+string+'\x1b[0m')

    def blue(self, string):
        print('\x1b[0;3'+str(self.colours['blue'])+';40m'+string+'\x1b[0m')

    def bright_blue(self, string):
        print('\x1b[1;3'+str(self.colours['blue'])+';40m'+string+'\x1b[0m')

    def purple(self, string):
        print('\x1b[0;3'+str(self.colours['purple'])+';40m'+string+'\x1b[0m')

    def bright_purple(self, string):
        print('\x1b[1;3'+str(self.colours['purple'])+';40m'+string+'\x1b[0m')

    def cyan(self, string):
        print('\x1b[0;3'+str(self.colours['cyan'])+';40m'+string+'\x1b[0m')

    def bright_cyan(self, string):
        print('\x1b[1;3'+str(self.colours['cyan'])+';40m'+string+'\x1b[0m')

    def white(self, string):
        print('\x1b[0;3'+str(self.colours['white'])+';40m'+string+'\x1b[0m')

    def bright_white(self, string):
        print('\x1b[1;3'+str(self.colours['white'])+';40m'+string+'\x1b[0m')
