/*
 * This file is part of WebSphinx.
 * Copyright (C) 2017 Iwan Timmer
 * Copyright (C) 2018 pitchfork@ctrlc.hu
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

const APP_NAME = "websphinx";

var browser = browser || chrome;

class Sphinx {
  constructor(input, results) {
    this.input = input;
    this.results = results;
    this.selectionIndex = -1;
    this.site = '';
    this.background = browser.runtime.connect();

    this.input.setAttribute("placeholder", browser.i18n.getMessage("searchPlaceholder"));
    //this.input.addEventListener("input", this.onInput.bind(this));
    this.input.addEventListener("keydown", this.onKeyDown.bind(this));
    this.input.addEventListener("blur", this.onBlur.bind(this));
    browser.tabs.query({ currentWindow: true, active: true }, this.onTabs.bind(this));

    var self = this;
    this.background.onMessage.addListener(function(response) {
      while (self.results.firstChild)
        self.results.removeChild(self.results.firstChild);

      for (let result of response.results.names) {
        let domain = result.split('/').reverse()[0];

        let item = document.createElement("li");
        let button = document.createElement("button");
        //let favicon = document.createElement("img");
        let label = document.createElement("span");

        label.textContent = result;
        button.addEventListener("click", self.onClick.bind(self));

        button.appendChild(label);
        item.appendChild(button);
        self.results.appendChild(item);
      }
    });

    setTimeout(() => {
      this.input.focus();
    }, 100);
  }

  search(query) {
    if (!query) {
      while (this.results.firstChild)
        this.results.removeChild(this.results.firstChild);
      return;
    }
    this.background.postMessage({
      action: "list",
      site: query
    });
  }

  onTabs(tabs) {
    if (tabs[0] && tabs[0].url)
      this.site = new URL(tabs[0].url).hostname;
      this.search(this.site);
  }

  onInput(event) {
    this.search(this.input.value.length > 0 ? this.input.value : null);
  }

  onClick(event) {
    this.background.postMessage({ "action": "login", "site": this.site, "name": event.target.textContent });
    window.close();
  }

  onBlur(event) {
    if (this.results.children[this.selectionIndex])
      this.results.children[this.selectionIndex].className = null;

    this.selectionIndex = -1;
  }

  onKeyDown(event) {
    if (event.keyCode == 0x0d && this.results.children[this.selectionIndex]) {
      this.background.postMessage({ "action": "login", "site": this.site, "name": this.results.children[this.selectionIndex].textContent });
      window.close();
    } else if (event.keyCode == 0x26 && this.selectionIndex > 0)
      this.selectionIndex--;
    else if (event.keyCode == 0x28 && this.selectionIndex < this.results.childElementCount - 1)
      this.selectionIndex++;
    else
      return;

    for (let e of this.results.getElementsByClassName('focus'))
      e.className = null;

    this.results.children[this.selectionIndex].className = "focus";
    event.preventDefault();
  }
}

document.addEventListener("DOMContentLoaded", function(event) {
  new Sphinx(document.getElementById("search"), document.getElementById("results"));
});
