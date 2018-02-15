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

var self = null;

const rules = [{"title": "Upper", "value": 'u',},
               {"title": "Lower", "value": 'l'},
               {"title": "Symbols", "value": "s"},
               {"title": "Digits", "value": "d"}];

class Sphinx {
  constructor(ui) {
    this.ui = ui;
    this.selectionIndex = -1;
    this.site = '';
    this.user = '';
    this.mode = '';
    this.inputs = 0;
    this.background = browser.runtime.connect();

    browser.tabs.query({ currentWindow: true, active: true }, this.onTabs.bind(this));

    self = this;
  }

  userList() {
    let input = document.createElement("input");
    input.id="search";
    input.autocomplete="off";
    input.autofocus="on";

    this.ui.appendChild(input);
    input.setAttribute("placeholder", browser.i18n.getMessage("searchPlaceholder"));
    input.addEventListener("keydown", this.onKeyDown.bind(this));
    input.addEventListener("blur", this.onBlur.bind(this));
    setTimeout(() => {
      input.focus();
    }, 100);

    let ul = document.createElement("ul");
    ul.id="results";
    for (let result of this.users) {
      let domain = result.split('/').reverse()[0];

      let item = document.createElement("li");
      let button = document.createElement("button");
      //let favicon = document.createElement("img");
      let label = document.createElement("span");

      label.textContent = result;
      button.addEventListener("click", this.onClick.bind(this));

      button.appendChild(label);
      item.appendChild(button);
      ul.appendChild(item);
    }
    this.ui.appendChild(ul);
  }

  create_opts() {
    for (let rule of rules) {
      let item = document.createElement("li");
      let checkbox = document.createElement("input");
      checkbox.type="checkbox";
      checkbox.name=rule["title"];
      checkbox.id=rule["title"];
      checkbox.value=rule["value"];
      checkbox.checked="checked";
      //let favicon = document.createElement("img");
      let label = document.createElement("label");
      label.for=rule["title"];
      label.textContent = rule["title"];
      item.appendChild(checkbox);
      item.appendChild(label);
      this.ui.appendChild(item);
    }
    let input = document.createElement("input");
    input.id="search";
    input.autocomplete="off";
    input.autofocus="on";
    this.ui.appendChild(input);
    input.setAttribute("placeholder", browser.i18n.getMessage("sizePlaceholder"));
    input.addEventListener("keydown", this.onKeyDownCreate.bind(this));
    setTimeout(() => {
      input.focus();
    }, 100);
    let button = document.createElement("button");
    let label = document.createElement("span");
    label.textContent = "Create";
    button.appendChild(label);
    this.ui.appendChild(button);
    button.addEventListener("click", this.onClickCreate.bind(this));
  }

  commit_ui() {
    while (this.ui.firstChild)
      this.ui.removeChild(this.ui.firstChild);

    let button = document.createElement("button");
    let label = document.createElement("span");
    label.textContent = "Save changed password";
    button.appendChild(label);
    this.ui.appendChild(button);
    button.addEventListener("click", this.onClickCommit.bind(this));
  }

  decide() {
    if(this.inputs == 1) { // one password field -> probably login
      // only one user in our db - use that to auto login
      if(this.users.length == 1) {
        this.background.postMessage({ "action": "login", "site": this.site, "name": this.users[0] });
        window.close();
        return;
      }
      // user set in the forms user field, auto select that user
      for(let user of this.users) {
        if(user == this.user && user != '') {
          this.background.postMessage({ "action": "login", "site": this.site, "name": user });
          window.close();
          return;
        }
      }
      // can't decide let user select which username to use for login
      this.mode = "login";
      this.userList();
    } else if(this.inputs == 2) { // 2 password fields -> either create user, or login with OTP field.
      if(this.users.length == 0) { // no users associated wit this site, should be a register form
        this.create_opts();
        return;
      }
      // if there is already a user specified in the username field
      // and that is a registered user with us, then we assume it's a
      // login form
      for(let user of this.users) {
        if(user == this.user && user != '') {
          this.background.postMessage({ "action": "login", "site": this.site, "name": user });
          window.close();
          return;
        }
      }
      // unsure: could be a login form with an OTP field, but could also be a registration form.
      // todo build UI to select mode, and depending on that do either thing.
      this.create_opts();
      return;
    } else if(this.inputs == 3) { // probably change password field
      if(this.users.length == 0) { // no users associated wit this site, can't be a change password form
        // todo handle this case, but how?
        return;
      }
      if(this.users.length == 1) { // we have only one registered user with this site, so it's easy
        this.background.postMessage({ "action": "change", "site": this.site, "name": this.users[0] });
        window.close();
        return;
      }
      // choose user to change password for
      this.mode = "change";
      this.userList();
    } else {
      console.log("are you kidding me?");
    }
  }

  recon_cb(response) {
    browser.runtime.onMessage.removeListener(self.recon_cb);
    console.log(response);
    self.user = response.username;
    self.inputs = response.password_fields;
    self.decide();
  }

  get_users_cb(response) {
    self.background.onMessage.removeListener(self.get_users_cb);
    console.log(response);
    if(response.results) {
      self.users = response.results.names;
    }

    // now also figure out what this page is about
    browser.tabs.executeScript({ file: '/inject.js', allFrames: true }, function() {
      browser.tabs.executeScript({code: 'document.websphinx.recon();'});
    });
  }

  onTabs(tabs) {
    // clear user list
    while (this.ui.firstChild)
      this.ui.removeChild(this.ui.firstChild);

    if (tabs[0] && tabs[0].url) {
      this.site = new URL(tabs[0].url).hostname;
    }

    browser.runtime.onMessage.addListener(this.recon_cb);
    this.background.onMessage.addListener(this.get_users_cb);

    // first get users associated with this site
    this.background.postMessage({
      action: "list",
      site: this.site
    });
  }

  onBlur(event) {
    let results = document.getElementById("results");
    if (results.children[this.selectionIndex])
      results.children[this.selectionIndex].className = null;

    this.selectionIndex = -1;
  }

  commit_cb(response) {
    self.background.onMessage.removeListener(self.commit_cb);
    console.log(response);
    // todo better handling
  }

  onClickCommit(event) {
    this.background.onMessage.addListener(this.commit_cb);
    this.background.postMessage({ "action": "commit", "site": this.site, "name": this.user });
    window.close();
  }

  onClick(event) {
    this.background.postMessage({ "action": this.mode, "site": this.site, "name": event.target.textContent });
    if(this.mode == 'login') window.close();
    else if(this.mode == 'change'){
      this.user = event.target.textContent;
      this.commit_ui();
    }
  }

  onKeyDown(event) {
    let results = document.getElementById("results");
    if (event.keyCode == 0x0d && results.children[this.selectionIndex]) {
      this.background.postMessage({ "action": this.mode, "site": this.site, "name": results.children[this.selectionIndex].textContent });
      if(this.mode != 'login') window.close();
      else this.commit_ui();
    } else if (event.keyCode == 0x26 && this.selectionIndex > 0)
      this.selectionIndex--;
    else if (event.keyCode == 0x28 && this.selectionIndex < results.childElementCount - 1)
      this.selectionIndex++;
    else
      return;

    for (let e of results.getElementsByClassName('focus'))
      e.className = null;

    results.children[this.selectionIndex].className = "focus";
    event.preventDefault();
  }

  submitCreate() {
    // get character class rules
    let r = "";
    for (let rule of rules) {
      var checkbox = document.getElementById(rule['title']);
      if(checkbox.checked) r+=rule['value'];
    }
    if(r=="") {
      //todo signal error
      return;
    }
    // get password size
    let size = 0;
    let input = document.getElementById('search');
    if(input.value != '') {
      try { size = Number(input.value) } catch (e) {
        // todo signal error
        return;
      }
    }
    if(this.user == '') {
      // todo signal error
      return;
    }
    this.background.postMessage({ "action": "create", "site": this.site, "name": this.user, "rules": r, "size": size });
    window.close();
  }

  onKeyDownCreate(event) {
    if (event.keyCode == 0x0d) {
      this.submitCreate();
      event.preventDefault();
    }
  }

  onClickCreate(event) {
    this.submitCreate();
  }
}

document.addEventListener("DOMContentLoaded", function(event) {
  new Sphinx(document.getElementById("ui"));
});
