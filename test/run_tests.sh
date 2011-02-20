#! /bin/sh
# ***************************************************************************
# *                                                                         *
# *   Copyright (C) 2011 Robert Hogan <robert@roberthogan.net>         *
# *                                                                         *
# *   This program is free software; you can redistribute it and/or modify  *
# *   it under the terms of the GNU General Public License as published by  *
# *   the Free Software Foundation; either version 2 of the License, or     *
# *   (at your option) any later version.                                   *
# *                                                                         *
# *   This program is distributed in the hope that it will be useful,       *
# *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
# *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
# *   GNU General Public License for more details.                          *
# *                                                                         *
# *   You should have received a copy of the GNU General Public License     *
# *   along with this program; if not, write to the                         *
# *   Free Software Foundation, Inc.,                                       *
#*   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
# ***************************************************************************
export TORSOCKS_DEBUG=2
TORSOCKS="`which torsocks`"

if [ ! -x "$TORSOCKS" ]; then
    echo "torsocks doesn't exist." >&2
    echo "Perhaps you haven't installed torsocks yet?" >&2
    exit 1
fi

if [ ! -f ./test_torsocks ]; then
    echo "test_torsocks binary doesn't exist in this directory." >&2
    echo "Perhaps you haven't compiled torsocks yet?" >&2
    exit 1
fi

torsocks ./test_torsocks > /tmp/newresults.txt 2>&1
output=`diff expectedresults.txt /tmp/newresults.txt`
if ["$output" = ""]; then
  echo "Tests passed"
else
  echo "Tests failed. Please post this output to http://code.google.com/p/torsocks/issues/entry"
fi
rm -f /tmp/newresults.txt
export TORSOCKS_DEBUG=