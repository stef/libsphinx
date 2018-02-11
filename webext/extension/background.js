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

nativeport.onMessage.addListener((response) => {
  if (browser.runtime.lastError) {
    var error = browser.runtime.lastError.message;
    console.error(error);
    portFromCS.postMessage({ status: "ERROR", error: error });
  } else if(response.results.cmd == 'show') {
    browser.tabs.executeScript({ file: '/inject.js', allFrames: true }, function() {
      let login = {
        username: response.results.name,
        password: response.results.password
      };
      browser.tabs.executeScript({code: 'document.websphinx.login(' + JSON.stringify(login) + ');'});
    });
  } else if(response.results.cmd == 'list') {
      portFromCS.postMessage(response);
  }
});

browser.runtime.onConnect.addListener(function(p) {
  portFromCS = p;

  // proxy from CS to native backend
  portFromCS.onMessage.addListener(function(request, sender, sendResponse) {
    if (request.action == "login") {
      nativeport.postMessage({
        cmd: "show",
        site: request.site,
        name: request.name});
    } else if (request.action == "list") {
      nativeport.postMessage({
        cmd: "list",
        site: request.site});
    }
  });
});
