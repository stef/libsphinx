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

class Sphinx {
  constructor() {
    this.selectionIndex = -1;
    this.site = '';
    this.user = '';
    this.users = [];
    this.mode = '';
    this.inputs = 0;
    this.background = browser.runtime.connect();

    browser.tabs.query({ currentWindow: true, active: true }, this.onTabs.bind(this));

    // tabs + close
    document.getElementById("login_tab").addEventListener("click",this.switchTab.bind(this));
    document.getElementById("create_tab").addEventListener("click",this.switchTab.bind(this));
    document.getElementById("change_tab").addEventListener("click",this.switchTab.bind(this));
    document.getElementById("close").addEventListener("click",this.closeWin.bind(this));

    // manual get/insert buttons
    document.getElementById("login_pwd").addEventListener("click",this.getpwd);
    document.getElementById("old_pwd").addEventListener("click",this.getpwd);
    document.getElementById("new_pwd").addEventListener("click",this.newpwd);
    document.getElementById("create_pwd").addEventListener("click",this.createpwd);
    document.getElementById('save_pwd').addEventListener("click", this.onClickCommit.bind(this));

    document.getElementById("autofill").addEventListener("click", this.onAutoClick);

    this.search = document.getElementById("search");
    this.search.setAttribute("placeholder", browser.i18n.getMessage("searchPlaceholder"));
    this.search.addEventListener("keydown", this.onKeyDown.bind(this));
    this.search.addEventListener("blur", this.onBlur.bind(this));

    self = this;
  }

  userList() {
    let autofill = document.getElementById("autofill");
    if(this.user!='') {
      this.search.value=this.user;
      autofill.removeEventListener("click", this.submitCreate);
      autofill.addEventListener("click", this.onAutoClick);
      autofill.className = "insert";
    } else {
      autofill.className = "hidden";
    }
    setTimeout(() => {
      this.search.focus();
    }, 100);

    let ul = document.getElementById("results");
    if(ul.firstChild == null && this.users.length>0) {
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
    }
  }

  create_opts() {
    this.select_tab('create');

    let size_wdgt = document.getElementById("pwdlen");
    size_wdgt.setAttribute("placeholder", browser.i18n.getMessage("sizePlaceholder"));
    size_wdgt.addEventListener("keydown", this.onKeyDownCreate.bind(this));

    if(this.user == '') {
      setTimeout(() => {
        this.search.focus();
      }, 100);
    } else {
      this.search.value=this.user;
      setTimeout(() => {
        size_wdgt.focus();
      }, 100);
    }
    let autofill = document.getElementById("autofill");
    autofill.removeEventListener("click", this.onAutoClick);
    autofill.addEventListener("click", this.submitCreate);
    autofill.className = "insert";
  }

  decide() {
    if(this.inputs == 1) { // one password field -> probably login
      // only one user in our db - use that to auto login
      this.mode = 'login';
      this.select_tab('login');

      if(this.users.length == 1) {
        //this.background.postMessage({ "action": "login", "site": this.site, "name": this.users[0], "mode": "insert" });
        this.user = this.users[0];
        //window.close();
        //return;
      }
      // user set in the forms user field, auto select that user
      for(let user of this.users) {
        if(user == this.user && user != '') {
          //this.background.postMessage({ "action": "login", "site": this.site, "name": user, "mode": "insert" });
          this.user = user;
          break;
          //window.close();
          //return;
        }
      }
      // can't decide let user select which username to use for login
      this.userList();
    } else if(this.inputs == 2) {
      // 2 password fields -> either create user, or login with OTP field.
      if(this.users.length == 0) { // no users associated wit this site, should be a register form
        this.create_opts();
        return;
      }
      // if there is already a user specified in the username field
      // and that is a registered user with us, then we assume it's a
      // login form
      for(let user of this.users) {
        if(user == this.user && user != '') {
          //this.background.postMessage({ "action": "login", "site": this.site, "name": user, "mode": "insert" });
          //window.close();
          this.user = user;
          this.userList();
          return;
        }
      }
      // unsure: could be a login form with an OTP field, but could also be a registration form.
      this.create_opts();
      return;
    } else if(this.inputs == 3) { // probably change password field
      if(this.users.length == 0) { // no users associated wit this site, can't be a change password form
        // todo handle this case, but how?
        this.create_opts();
        return;
      }
      if(this.users.length == 1) { // we have only one registered user with this site, so it's easy
        //this.background.postMessage({ "action": "change", "site": this.site, "name": this.users[0], "mode": "insert" });
        this.user = this.users[0];
        //window.close();
        //return;
      }
      // choose user to change password for
      this.select_tab('change');
      this.mode = "change";
      this.userList();
    } else {
      console.log("are you kidding me?");
    }
  }

  recon_cb(response) {
    browser.runtime.onMessage.removeListener(self.recon_cb);
    //console.log(response);
    self.user = response.username;
    self.inputs = response.password_fields;
    self.decide();
  }

  get_users_cb(response) {
    self.background.onMessage.removeListener(self.get_users_cb);
    //console.log(response);
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
    let results = document.getElementById("results");
    while (results.firstChild)
      results.removeChild(results.firstChild);

    if (tabs[0] && tabs[0].url) {
      this.site = new URL(tabs[0].url).hostname;
    }

    browser.runtime.onMessage.addListener(this.recon_cb);
    this.background.onMessage.addListener(this.get_users_cb);

    // first get users associated with this site
    this.background.postMessage({
      action: "list",
      mode: "init",
      site: this.site
    });
  }

  onBlur(event) {
    let results = document.getElementById("results");
    if (results.children[this.selectionIndex])
      results.children[this.selectionIndex].className = '';

    this.selectionIndex = -1;
  }

  onClickCommit(event) {
    this.background.postMessage({ "action": "commit", "site": this.site, "name": this.user, "mode": "" });
    // todo instead of closing the window perhaps provide some feedback regarding (non-)success of this op?
    window.close();
  }

  onAutoClick(event) {
    self.background.postMessage({ "action": self.mode, "site": self.site, "name": self.search.value, "mode": "insert" });
  }

  onClick(event) {
    this.background.postMessage({ "action": this.mode, "site": this.site, "name": event.target.textContent, "mode": "insert" });
  }

  onKeyDown(event) {
    let results = document.getElementById("results");
    if (event.keyCode == 0x0d) {
      if(this.search.value!='') {
          this.background.postMessage({ "action": this.mode, "site": this.site, "name": this.search.value, "mode": "insert" });
      } else if(results.children[this.selectionIndex]) {
        this.background.postMessage({ "action": this.mode, "site": this.site, "name": results.children[this.selectionIndex].textContent, "mode": "insert" });
      }
    } else if (event.keyCode == 0x26 && this.selectionIndex > 0)
      this.selectionIndex--;
    else if (event.keyCode == 0x28 && this.selectionIndex < results.childElementCount - 1)
      this.selectionIndex++;
    else
      return;

    for (let e of results.getElementsByClassName('focus'))
      e.className = '';

    if(this.selectionIndex >= 0 && this.selectionIndex < results.childElementCount) {
      results.children[this.selectionIndex].className = "focus";
    }
    event.preventDefault();
  }

  flashError(el) {
    el.style="background: red;";
    setTimeout(() => {
      el.focus();
    }, 100);
    setTimeout(() => {
      el.style='';
    }, 1000);
  }

  getpwdrules() {
    const rules = [{"title": "Upper", "value": 'u',},
                   {"title": "Lower", "value": 'l'},
                   {"title": "Symbols", "value": "s"},
                   {"title": "Digits", "value": "d"}];

    // get character class rules
    let r = "";
    for (let rule of rules) {
      let checkbox = document.getElementById(rule['title']);
      if(checkbox.checked) r+=rule['value'];
    }
    if(r=="") {
      for (let rule of rules) {
        let checkbox = document.getElementById(rule['title']);
        let label = checkbox.nextSibling;
        label.style="background: red;";
        setTimeout(() => {
          checkbox.focus();
        }, 100);
        setTimeout(() => {
          label.style='';
        }, 1000);
      }
      return;
    }
    // get password size
    let size = 0;
    let input = document.getElementById('pwdlen');
    if(input.value != '') {
      try { size = Number(input.value) } catch (e) {
        this.sizeError(input);
        return;
      }
    }
    if(isNaN(size)) {
      this.flashError(input);
      return;
    }
    return [r,size];
  }

  submitCreate() {
    let r_ = self.getpwdrules();
    if (r_ == null) return;
    let r=r_[0], size = r_[1];

    if(self.user == '') {
      if(self.search.value == '') {
        self.flashError(self.search);
        return;
      }
      // we assume the value of the search field to be the username to be created
      self.user = self.search.value;
    }
    self.background.postMessage({ "action": "create", "site": self.site, "name": self.user, "rules": r, "size": size, "mode": "insert" });
    //window.close();
  }

  onKeyDownCreate(event) {
    if (event.keyCode == 0x0d) {
      this.submitCreate();
      event.preventDefault();
    }
  }

  select_tab(tabid) {
    let tab = document.getElementById(tabid+'_tab');
    this.switchTab({target: tab});
  }

  switchTab(event) {
    let tabs = document.getElementById("tabs");
    for (let selected of tabs.getElementsByClassName('selected')) {
      selected.className="inactive";
      selected.addEventListener("click",self.switchTab.bind(self));
      selected = document.getElementById(selected.id.slice(0,-4));
      selected.className="hidden";
      let tab = selected.id.slice(0,-4);
      // remove event listeners
      if(tab == "create") {
          this.search.removeEventListener("keydown", this.onKeyDownCreate);
      } else {
          this.search.removeEventListener("keydown", this.onKeyDown);
          this.search.removeEventListener("blur", this.onBlur);
      }
    }
    event.target.className="selected";
    event.target.removeEventListener("click", self.switchTab);

    this.mode = event.target.id.slice(0,-4);
    let selected = document.getElementById(this.mode);
    selected.className=null;
    let results = document.getElementById("results");
    if(event.target.id.slice(0,-4)=="create") {
      results.className = "hidden";
      this.search.addEventListener("keydown", this.onKeyDownCreate.bind(this));
    } else {
      results.className = null;
      if(document.getElementById("results").firstChild == null && this.users.length>0) {
        this.userList();
      } else {
        this.search.addEventListener("keydown", this.onKeyDown.bind(this));
        this.search.addEventListener("blur", this.onBlur.bind(this));
      }
    }
  }

  closeWin() {
    window.close();
  }

  fetchpwd(el, eh, mode, rules, size) {
    if(this.user == '') {
      if(this.search.value == '') {
        this.flashError(this.search);
        return;
      }
      // we assume the value of the search field to be the username to be created
      this.user = this.search.value;
    }

    this.background.postMessage({ "action": mode,
                                  "site": this.site,
                                  "name": this.user,
                                  "rules": rules,       // optional only used with create
                                  "size": size,         // optional only used with create
                                  "mode": "manual" });  // needed for background to trigger proper callback
  }

  getpwd(e) {
    self.fetchpwd(e.target, self.getpwd, "login", null, null);
  }

  newpwd(e) {
    self.fetchpwd(e.target, self.newpwd, "change", null, null);
  }

  createpwd(e) {
    let r_ = self.getpwdrules();
    if (r_ == null) return;
    let r=r_[0], size = r_[1];
    self.fetchpwd(e.target, self.createpwd, "create", r, size);
  }

}

document.addEventListener("DOMContentLoaded", function(event) {
  new Sphinx();
});
