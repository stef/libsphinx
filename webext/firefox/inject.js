/*
 * This file is part of WebSphinx.
 * Copyright (c) 2016 Danny van Kooten
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

var browser = browser || chrome;

(function(doc) {
  const FORM_MARKERS = [
    "login",
    "log-in",
    "log_in",
    "signin",
    "sign-in",
    "sign_in"
  ];
  const USERNAME_FIELDS = {
    selectors: [
      "input[name*=user i]",
      "input[name*=login i]",
      "input[name*=email i]",
      "input[id*=user i]",
      "input[id*=login i]",
      "input[id*=email i]",
      "input[class*=user i]",
      "input[class*=login i]",
      "input[class*=email i]",
      "input[type=email i]",
      "input[type=text i]",
      "input[type=tel i]"
    ],
    types: ["email", "text", "tel"]
  };
  const PASSWORD_FIELDS = {
    selectors: ["input[type=password i]"]
  };
  const INPUT_FIELDS = {
    selectors: PASSWORD_FIELDS.selectors.concat(USERNAME_FIELDS.selectors)
  };
  const SUBMIT_FIELDS = {
    selectors: [
      "[type=submit i]",
      "button[name*=login i]",
      "button[name*=log-in i]",
      "button[name*=log_in i]",
      "button[name*=signin i]",
      "button[name*=sign-in i]",
      "button[name*=sign_in i]",
      "button[id*=login i]",
      "button[id*=log-in i]",
      "button[id*=log_in i]",
      "button[id*=signin i]",
      "button[id*=sign-in i]",
      "button[id*=sign_in i]",
      "button[class*=login i]",
      "button[class*=log-in i]",
      "button[class*=log_in i]",
      "button[class*=signin i]",
      "button[class*=sign-in i]",
      "button[class*=sign_in i]",
      "input[type=button i][name*=login i]",
      "input[type=button i][name*=log-in i]",
      "input[type=button i][name*=log_in i]",
      "input[type=button i][name*=signin i]",
      "input[type=button i][name*=sign-in i]",
      "input[type=button i][name*=sign_in i]",
      "input[type=button i][id*=login i]",
      "input[type=button i][id*=log-in i]",
      "input[type=button i][id*=log_in i]",
      "input[type=button i][id*=signin i]",
      "input[type=button i][id*=sign-in i]",
      "input[type=button i][id*=sign_in i]",
      "input[type=button i][class*=login i]",
      "input[type=button i][class*=log-in i]",
      "input[type=button i][class*=log_in i]",
      "input[type=button i][class*=signin i]",
      "input[type=button i][class*=sign-in i]",
      "input[type=button i][class*=sign_in i]"
    ]
  };
  
  function queryAllVisible(parent, field, form) {
    var result = [];
    for (var i = 0; i < field.selectors.length; i++) {
      var elems = parent.querySelectorAll(field.selectors[i]);
      for (var j = 0; j < elems.length; j++) {
        var elem = elems[j];
        // Select only elements from specified form
        if (form && form != elem.form) {
          continue;
        }
        // Ignore disabled fields
        if (elem.disabled) {
          continue;
        }
        // Elem or its parent has a style 'display: none',
        // or it is just too narrow to be a real field (a trap for spammers?).
        if (elem.offsetWidth < 30 || elem.offsetHeight < 10) {
          continue;
        }
        // We may have a whitelist of acceptable field types. If so, skip elements of a different type.
        if (field.types && field.types.indexOf(elem.type.toLowerCase()) < 0) {
          continue;
        }
        // Elem takes space on the screen, but it or its parent is hidden with a visibility style.
        var style = window.getComputedStyle(elem);
        if (style.visibility == "hidden") {
          continue;
        }
        // Elem is outside of the boundaries of the visible viewport.
        var rect = elem.getBoundingClientRect();
        if (
          rect.x + rect.width < 0 ||
          rect.y + rect.height < 0 ||
          (rect.x > window.innerWidth || rect.y > window.innerHeight)
        ) {
          continue;
        }
        // This element is visible, will use it.
        result.push(elem);
      }
    }
    return result;
  }
  
  function queryFirstVisible(parent, field, form) {
    var elems = queryAllVisible(parent, field, form);
    return elems.length > 0 ? elems[0] : undefined;
  }
  
  function form() {
    var elems = queryAllVisible(document, INPUT_FIELDS, undefined);
    var forms = [];
    for (var i = 0; i < elems.length; i++) {
      var form = elems[i].form;
      if (form && forms.indexOf(form) < 0) {
        forms.push(form);
      }
    }
    if (forms.length == 0) {
      return undefined;
    }
    if (forms.length == 1) {
      return forms[0];
    }
  
    // If there are multiple forms, try to detect which one is a login form
    var formProps = [];
    for (var i = 0; i < forms.length; i++) {
      var form = forms[i];
      var props = [form.id, form.name, form.className];
      formProps.push(props);
      for (var j = 0; j < FORM_MARKERS.length; j++) {
        var marker = FORM_MARKERS[j];
        for (var k = 0; k < props.length; k++) {
          var prop = props[k];
          if (prop.toLowerCase().indexOf(marker) > -1) {
            return form;
          }
        }
      }
    }
  
    console.error(
      "Unable to detect which of the multiple available forms is the login form. Please submit an issue for browserpass on github, and provide the following list in the details: " +
        JSON.stringify(formProps)
    );
    return forms[0];
  }
  
  function find(field) {
    return queryFirstVisible(document, field, form());
  }
  
  function update(field, value) {
    if (!value.length) {
      return false;
    }
  
    // Focus the input element first
    var el = find(field);
    if (!el) {
      return false;
    }
    var eventNames = ["click", "focus"];
    eventNames.forEach(function(eventName) {
      el.dispatchEvent(new Event(eventName, { bubbles: true }));
    });
  
    // Focus may have triggered unvealing a true input, find it again
    el = find(field);
    if (!el) {
      return false;
    }
  
    // Now set the value and unfocus
    el.setAttribute("value", value);
    el.value = value;
    eventNames = [
      "keypress",
      "keydown",
      "keyup",
      "input",
      "blur",
      "change"
    ];
    eventNames.forEach(function(eventName) {
      el.dispatchEvent(new Event(eventName, { bubbles: true }));
    });
    return true;
  }
  
  function update_all(field, value) {
    if (!value.length) {
      return false;
    }
  
    let password_inputs = queryAllVisible(document, PASSWORD_FIELDS, form());
    password_inputs.forEach(function(el) {
      let eventNames = ["click", "focus"];
      eventNames.forEach(function(eventName) {
        el.dispatchEvent(new Event(eventName, { bubbles: true }));
      });
  
      // Focus may have triggered unvealing a true input, find it again
      let pwd_inputs = queryAllVisible(document, PASSWORD_FIELDS, form());
      pwd_inputs.forEach(function(el2) {
        // Now set the value and unfocus
        el2.setAttribute("value", value);
        el2.value = value;
        let eventNames = [
          "keypress",
          "keydown",
          "keyup",
          "input",
          "blur",
          "change"
        ];
        eventNames.forEach(function(eventName) {
          el2.dispatchEvent(new Event(eventName, { bubbles: true }));
        });
      });
    });
    return true;
  }
  
  function set_pwd(el, value) {
    let eventNames = ["click", "focus"];
    eventNames.forEach(function(eventName) {
      el.dispatchEvent(new Event(eventName, { bubbles: true }));
    });
  
    // Focus may have triggered unvealing a true input, find it again
    //let pwd_inputs = queryAllVisible(document, PASSWORD_FIELDS, form());
    // we ignore this for now
    //pwd_inputs.forEach(function(el2) {
  
    // Now set the value and unfocus
    el.setAttribute("value", value);
    el.value = value;
    eventNames = [
      "keypress",
      "keydown",
      "keyup",
      "input",
      "blur",
      "change"
    ];
    eventNames.forEach(function(eventName) {
      el.dispatchEvent(new Event(eventName, { bubbles: true }));
    });
    //});
  }
  class WebSphinx {

    recon() {
      var username = '';
        var el = find(USERNAME_FIELDS);
        if(el) {
          username=el.value;
        }
        var password_inputs = queryAllVisible(document, PASSWORD_FIELDS, form());
        browser.runtime.sendMessage({"username": username, "password_fields": password_inputs.length});
    };

    login(login) {
      update(USERNAME_FIELDS, login.username);
      update(PASSWORD_FIELDS, login.password);

      var password_inputs = queryAllVisible(document, PASSWORD_FIELDS, form());
      if (password_inputs.length > 1) {
        // There is likely a field asking for OTP code, so do not submit form just yet
        password_inputs[1].select();
      } else {
        window.requestAnimationFrame(function() {
          // Try to submit the form, or focus on the submit button (based on user settings)
          var submit = find(SUBMIT_FIELDS);
          if (submit) {
            submit.focus();
          } else {
            // There is no submit button. We need to keep focus somewhere within the form, so that Enter hopefully submits the form.
            var password = find(PASSWORD_FIELDS);
            if (password) {
              password.focus();
            } else {
              var username = find(USERNAME_FIELDS);
              if (username) {
                username.focus();
              }
            }
          }
        });
      }
    };

    create(account) {
      update(USERNAME_FIELDS, account.username);
      update_all(PASSWORD_FIELDS, account.password);

      window.requestAnimationFrame(function() {
        // Try to submit the form, or focus on the submit button (based on user settings)
        var submit = find(SUBMIT_FIELDS);
        if (submit) {
          submit.focus();
        } else {
          // There is no submit button. We need to keep focus somewhere within the form, so that Enter hopefully submits the form.
          var password = find(PASSWORD_FIELDS);
          if (password) {
            password.focus();
          }
        }
      });
    };

    change(changed) {
      var pwd_inputs = queryAllVisible(document, PASSWORD_FIELDS, form());
      if(pwd_inputs.length!=3) {
        console.log("wtf");
        console.log(pwd_inputs);
        return;
      }
      set_pwd(pwd_inputs[0],changed.old.password);
      set_pwd(pwd_inputs[1],changed.new.password);
      set_pwd(pwd_inputs[2],changed.new.password);

      window.requestAnimationFrame(function() {
        // Try to submit the form, or focus on the submit button (based on user settings)
        var submit = find(SUBMIT_FIELDS);
        if (submit) {
          submit.focus();
        } else {
          // There is no submit button. We need to keep focus somewhere within the form, so that Enter hopefully submits the form.
          var password = find(PASSWORD_FIELDS);
          if (password) {
            password.focus();
          }
        }
      });
    };

    inject(pwd) {
      let el = document.activeElement;
      if(el.type=="password") {
        set_pwd(el, pwd);
      }
    }
  }
  doc.websphinx = new WebSphinx();
})(document);
