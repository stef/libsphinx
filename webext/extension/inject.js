/*
 * This file is part of WebSphinx.
 * Copyright (C) 2017 Iwan Timmer
 *
 * WebSphinx is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * WebSphinx is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

"use strict";

(function(doc) {
  class WebSphinx {
    login(login) {
      if (login.username) {
        let fields = doc.querySelectorAll("input[type=email], input[type=text], input:first-of-type");
        if (fields.length > 0)
          fields[0].value = login.username;
      }
      let fields = doc.querySelectorAll("input[type='password']");
      for (let field of fields)
        field.value = login.password;
    }
  }

  doc.websphinx = new WebSphinx();
})(document);
