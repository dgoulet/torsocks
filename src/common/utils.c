/*
 * Copyright (C) 2000-2008 - Shaun Clowes <delius@progsoc.org> 
 * 				 2008-2011 - Robert Hogan <robert@roberthogan.net>
 * 				 	  2013 - David Goulet <dgoulet@ev0ke.net>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License, version 2 only, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <string.h>

#include "macros.h"
#include "utils.h"

/*
 * This routines breaks up input lines into tokens and places these tokens into
 * the array specified by tokens
 *
 * Return the number of token plus one set in the given array.
 */
ATTR_HIDDEN
int utils_tokenize_ignore_comments(char *line, int arrsize, char **tokens)
{
	int tokenno = -1;
	int finished = 0;

	/* Whitespace is ignored before and after tokens     */
	while ((tokenno < (arrsize - 1)) &&
			(line = line + strspn(line, " \t")) &&
			(*line != (char) 0) &&
			(!finished)) {
		tokenno++;
		tokens[tokenno] = line;
		line = line + strcspn(line, " \t");
		*line = '\0';
		line++;

		/* We ignore everything after a # */
		if (*tokens[tokenno] == '#') {
			finished = 1;
			tokenno--;
		}
	}

	return tokenno + 1;
}

/*
 * This function is very much like strsep, it looks in a string for a character
 * from a list of characters, when it finds one it replaces it with a \0 and
 * returns the start of the string (basically spitting out tokens with
 * arbitrary separators).
 *
 * If no match is found the remainder of the string is returned and the start
 * pointer is set to be NULL. The difference between standard strsep and this
 * function is that this one will set separator to the character separator
 * found if it isn't NULL.
 */
ATTR_HIDDEN
char *utils_strsplit(char *separator, char **text, const char *search)
{
	unsigned int len;
	char *ret;

	ret = *text;

	if (*text == NULL) {
		if (separator) {
			*separator = '\0';
		}
		return NULL;
	}

	len = strcspn(*text, search);
	if (len == strlen(*text)) {
		if (separator) {
			*separator = '\0';
		}
		*text = NULL;
	} else {
		*text = *text + len;
		if (separator) {
			*separator = **text;
		}
		**text = '\0';
		*text = *text + 1;
	}

	return ret;
}
