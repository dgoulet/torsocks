/***************************************************************************
 *                                                                         *
 * $Id: saveme.c,v 1.2 2008-07-06 15:17:35 hoganrobert Exp $                            *
 *                                                                         *
 *   Copyright (C) 2008 by Robert Hogan                                    *
 *   robert@roberthogan.net                                                *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************
 *                                                                         *
 *   This is a modified version of a source file from the tsocks project.  *
 *   Original copyright notice from tsocks source file follows:            *
 *                                                                         *
 ***************************************************************************/
/* 

     SAVEME    - Part of the tsocks package
		 This program is designed to be statically linked so
		 that if a user breaks their ld.so.preload file and
		 cannot run any dynamically linked program it can 
		 delete the offending ld.so.preload file.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

*/

#include <stdio.h>
#include <unistd.h>

int main() {

	unlink("/etc/ld.so.preload");

   return(0);
}
