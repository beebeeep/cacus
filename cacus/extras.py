#!/usr/bin/env python3

import re


class DebVersion(object):
    """ Implements debian package version comparsion according to deb-version(5)
    I'm not responsible for those brain-dead people who invented this sick format and comparsion rules
    Same functionality is provided by python-apt, but it's poorly maintained
    """

    __version_re = re.compile(r'''^((?P<epoch>\d+):)?(?P<upstream>[-.+:~0-9A-z]+?)(-(?P<debian>[+.~0-9A-z]+))?$''')
    __digits_re = re.compile(r'''^(\d+)''')
    __nondigits_re = re.compile(r'''^([-.+:~A-z]+)''')

    # table for wicked debianish string comparsion
    __lexical_table = {
        '~': 0, '': 1, '+': 2, '-': 3, '.': 4, ':': 5
    }
    __lexical_table.update(dict((chr(x), x) for x in range(ord('A'), ord('z'))))

    def __init__(self, version):
        self.version = version.rstrip().lstrip()
        m = self.__version_re.match(self.version)
        if m:
            self.correct = True
            g = m.groupdict()
            self.epoch = int(g['epoch'] or 0)
            self.upstream = g['upstream']
            self.debian = g['debian']
        else:
            self.correct = False
            self.epoch = self.upstream = self.debian = None

    def __part_lt(self, x1, x2):
        """ returns True if x1 < x2 according to string comparsion rules defined in section "Sorting algorithm" of deb-version(5)
        """
        while True:
            if not x1 and not x2:
                # both strings exhausted, exit
                return False
            elif not x1:
                # otherwise complement None-s to empty string as emptiness matters
                x1 = ''
            elif not x2:
                x2 = ''

            # extract non-digit part from both strings
            m1 = self.__nondigits_re.search(x1)
            m2 = self.__nondigits_re.search(x2)
            s1 = m1.group(1) if m1 else ''
            s2 = m2.group(1) if m2 else ''
            len_s1 = len(s1)
            len_s2 = len(s2)
            i = -1
            while True:
                # compare both parts
                i = i + 1
                c1 = s1[i] if i < len_s1 else ''
                c2 = s2[i] if i < len_s2 else ''
                if c1 == '' and c2 == '':
                    break
                if c1 == c2:
                    continue
                if self.__lexical_table[c1] < self.__lexical_table[c2]:
                    return True
                if self.__lexical_table[c1] > self.__lexical_table[c2]:
                    return False

            # cut analyzed parts from string
            x1 = x1[len_s1:]
            x2 = x2[len_s2:]

            m1 = self.__digits_re.search(x1)
            m2 = self.__digits_re.search(x2)
            s1 = m1.group(1) if m1 else ''
            s2 = m2.group(1) if m2 else ''
            number1 = int(s1 or 0)
            number2 = int(s2 or 0)
            if number1 < number2:
                return True
            elif number1 > number2:
                return False

            # cut analyzed numbers from string and go over
            x1 = x1[len(s1):]
            x2 = x2[len(s2):]

    def __eq__(self, x):
        return self.__cmp__(x) == 0

    def __ne__(self, x):
        return self.__cmp__(x) != 0

    def __lt__(self, x):
        return self.__cmp__(x) < 0

    def __gt__(self, x):
        return self.__cmp__(x) > 0

    def __ge__(self, x):
        return self.__cmp__(x) >= 0

    def __le__(self, x):
        return self.__cmp__(x) <= 0

    def __cmp__(self, x):

        if self.epoch == x.epoch and self.upstream == x.upstream and self.debian == x.debian:
            return 0

        if not self.correct:
            # incorrect versions are always lesser
            return -1

        if self.epoch != x.epoch:
            if self.epoch < x.epoch:
                return -1
            else:
                return 1

        if self.upstream != x.upstream:
            if self.__part_lt(self.upstream, x.upstream):
                return -1
            else:
                return 1

        if self.debian != x.debian:
            if self.__part_lt(self.debian, x.debian):
                return -1
            else:
                return 1

        return 0
