/*
 * This file is part of WebSphinx.
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
var portFromCS;
var nativeport = browser.runtime.connectNative(APP_NAME);
var changeData = true;

nativeport.onMessage.addListener((response) => {
  if (browser.runtime.lastError) {
    var error = browser.runtime.lastError.message;
    console.error(error);
    portFromCS.postMessage({ status: "ERROR", error: error });
  } else if(response.results == 'fail') {
    console.log('websphinx failed');
  } else if(response.results.mode == "manual") {
    //console.log("manual");
    // its a manual mode response so we just pass it to the popup
    portFromCS.postMessage(response);
  } else if(response.results.cmd == 'show') {
    if(changeData==true) {
      // we got the old password
      changeData=response.results;
      // now change the password
      nativeport.postMessage({
        cmd: "change",
        mode: response.results.mode,
        site: response.results.site,
        name: response.results.name
      });
      return;
    }
    let login = {
      username: response.results.name,
      password: response.results.password
    };
    browser.tabs.executeScript({code: 'document.websphinx.login(' + JSON.stringify(login) + ');'});
  } else if(response.results.cmd == 'list') {
    portFromCS.postMessage(response);
  } else if(response.results.cmd == 'create') {
    let account = {
      username: response.results.name,
      password: response.results.password
    };
    browser.tabs.executeScript({code: 'document.websphinx.create(' + JSON.stringify(account) + ');'});
  } else if(response.results.cmd == 'change') {
    let change = {
      'old': changeData,
      'new': response.results
    }
    browser.tabs.executeScript({code: 'document.websphinx.change(' + JSON.stringify(change) + ');'});
    changeData = false;
  } else if(response.results.cmd == 'commit') {
    portFromCS.postMessage(response);
  }
});

browser.runtime.onConnect.addListener(function(p) {
  portFromCS = p;

  // proxy from CS to native backend
  portFromCS.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action == "login") {
      //console.log("login");
      changeData=false;
      nativeport.postMessage({
        cmd: "show",
        mode: request.mode,
        site: request.site,
        name: request.name});
    } else if (request.action == "list") {
      //console.log("list");
      nativeport.postMessage({
        cmd: request.action,
        mode: request.mode,
        site: request.site});
    } else if (request.action == "create") {
      //console.log("create");
      nativeport.postMessage({
        cmd: request.action,
        mode: request.mode,
        site: request.site,
        name: request.name,
        rules: request.rules,
        size: request.size
      });
    } else if (request.action == "change") {
      //console.log("change");
      if(request.mode == "manual") {
        nativeport.postMessage({
          cmd: "change",
          mode: request.mode,
          site: request.site,
          name: request.name
        });
      } else {
        // first get old password
        // but this will trigger the login inject in the nativport onmessage cb
        changeData = true;
        nativeport.postMessage({
          cmd: "show",
          mode: request.mode,
          site: request.site,
          name: request.name
        });
      }
    } else if (request.action == "commit") {
      //console.log("commit");
      nativeport.postMessage({
        cmd: request.action,
        mode: request.mode,
        site: request.site,
        name: request.name
      });
    }
  });
});
