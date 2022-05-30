#!/usr/bin/env python3

import fnmatch
import os

from termcolor import colored

from core import core
from core.config import RULES

FILETYPE = RULES['filetype']
FILETYPE_WEIGHT = RULES['filetype_weight']
GREP_WORDS = RULES['grep_words']
GREP_WORD_OCCURRENCE = RULES['grep_word_occurrence']
GREP_WORDS_WEIGHT = RULES['grep_words_weight']


class AdvancedSearch(object):

    def __init__(self):
        self._FILETYPE = FILETYPE
        self._FILETYPE_WEIGHT = FILETYPE_WEIGHT
        self._GREP_WORDS = GREP_WORDS
        self._GREP_WORD_OCCURRENCE = GREP_WORD_OCCURRENCE
        self._GREP_WORDS_WEIGHT = GREP_WORDS_WEIGHT
        self._OCCURRENCE_COUNTER = 0
        self._FINAL_WEIGHT = 0
        self._EXIST = True

    def grepper(self, word):
        for search_expression in self._GREP_WORDS:

            if fnmatch.fnmatch(word, search_expression):
                self._OCCURRENCE_COUNTER += 1

        if self._OCCURRENCE_COUNTER >= self._GREP_WORD_OCCURRENCE:
            self._FINAL_WEIGHT += self._GREP_WORDS_WEIGHT

    def filetype_check(self, _file):
        file_name, extension = os.path.splitext(_file)
        for ext in self._FILETYPE:

            if fnmatch.fnmatch(extension, ext):
                self._FINAL_WEIGHT += self._FILETYPE_WEIGHT

    def final(self, _file):
        if self._FINAL_WEIGHT < 10:
            return False
        print(colored("INTERESTING FILE HAS BEEN FOUND!!!", 'cyan'))
        print(colored("The rule defined in 'rules.yaml' file has been "
                      + "triggerred. Checkout the file " + _file, 'cyan'))
        core.logger.info("the rule defined in 'rules.yaml' file has been "
                         + "triggerred while analyzing file " + _file)

        return True

    @property
    def file_type(self) -> str:
        return self._FILETYPE

    @property
    def file_type_weight(self) -> str:
        return self._FILETYPE_WEIGHT

    @property
    def grep_words(self) -> str:
        return self._GREP_WORDS

    @property
    def grep_words_occurrence(self) -> str:
        return self._GREP_WORD_OCCURRENCE

    @property
    def grep_words_weight(self) -> str:
        return self._GREP_WORDS_WEIGHT
