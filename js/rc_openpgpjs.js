/*
+-------------------------------------------------------------------------+
| OpenPGP.js implemented in Roundcube.                                    |
|                                                                         |
| Copyright (C) Niklas Femerstrand <nik@qnrq.se>                          |
|                                                                         |
| This program is free software; you can redistribute it and/or modify    |
| it under the terms of the GNU General Public License version 2          |
| as published by the Free Software Foundation.                           |
|                                                                         |
| This program is distributed in the hope that it will be useful,         |
| but WITHOUT ANY WARRANTY; without even the implied warranty of          |
| MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
| GNU General Public License for more details.                            |
|                                                                         |
| You should have received a copy of the GNU General Public License along |
| with this program; if not, write to the Free Software Foundation, Inc., |
| 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.             |
|                                                                         |
+-------------------------------------------------------------------------+
*/

var VERSTR = "20131021";

var rc_openpgpjs_crypto = new (require('./rc_openpgpjs.crypto.js'))();
window.openpgp = require('openpgp');

if(window.rcmail) {
  rcmail.addEventListener("init", function() {
    if(!window.crypto || !window.crypto.getRandomValues) { // OpenPGP.js specific
      rcmail.display_message(rcmail.gettext("no_window_crypto", "rc_openpgpjs"), "error");
    }

    this.cleartext = null;
    this.ciphertext = null;

    // If we decide to encrypt or sign, we'll have to do it asynchronously.
    // Therefore, beforeSend will cancel the send and do its business.
    // When its business is done, it will trigger the send again.
    // We'll have to know that the business is done, so that we don't try to do
    // it again.  That's what this variable is for.
    this.finished_treating = false;

    rcmail.addEventListener("plugin.pks_search", pks_search_callback);

    // The sendPubkey function creates a Promise that should get resolved when
    // the server returns and this callback gets called.
    // Therefore, when we create the Promise, we will set
    // this.pubkey_save_resolve to be the resolve function.  When
    // pubkey_save_callback gets called, it will resolve the Promise by calling
    // this.pubkey_save_resolve.
    this.pubkey_save_resolve = null;
    rcmail.addEventListener("plugin.pubkey_save_callback", pubkey_save_callback);

    if(sessionStorage.length > 0) {
      this.passphrase = sessionStorage[0];
    }

    // This dialog contains a form which calls the set_passphrase function onsubmit.
    // It is set_passphrase's responsibility to close the dialog if the user
    // successfully chose a key and entered a passphrase.  But the user can
    // also click the X to close the dialog, in which case the close function
    // will be called, but no key is chosen and no passphrase is entered.

    // Wherever we are opening the dialog from, a Promise was created at that point.
    // We will want the set_passphrase function, or the close function here, to
    // be able to resolve that promise.  So the resolve and reject functions
    // are placed in this global variable.
    this.key_select_resolve_reject = null;

    // The close function is called when the key is selected, but it's also
    // called when the user cancels.  In order to distinguish these cases, we
    // have the key_selected global var, which will be set to true by
    // set_passphrase if we have successfully decrypted a key.
    this.key_selected = false;

    $("#openpgpjs_key_select").dialog({
      modal: true,
      autoOpen: false,
      title: rcmail.gettext("select_key", "rc_openpgpjs"),
      width: "30%",
      open: function() {
        updateKeySelector();
      },
      close: function() {
        if (window.key_selected) {
          // The user has successfully chosen a key.  Reset it to false for next time.
          window.key_selected = false;
        } else {
          key_select_resolve_reject.reject("User cancelled");
        }
        $("#selected_key_passphrase").val("");
        $("#openpgpjs_rememberpass").attr("checked", false);
      },
    });
	
    $("#openpgpjs_key_search").dialog({
      modal: true,
      autoOpen: false,
      title: rcmail.gettext("key_search", "rc_openpgpjs"),
      width: "60%",
      open: function() {
        $("#openpgpjs_search_results").html("");
        $("#openpgpjs_search_input").val("");
      }
    });

    $("#openpgpjs_key_manager").dialog({
      modal: true,
      autoOpen: false,
      title: rcmail.gettext("key_manager", "rc_openpgpjs"),
      width: "90%",
      open: function() {
        updateKeyManager();
      }
    });

    $("#openpgpjs_tabs").tabs();

    // register open key manager command
    rcmail.register_command("open-key-manager", function() {
      $("#openpgpjs_key_manager").dialog("open");
    });
    rcmail.enable_command("open-key-manager", true);

    if(rcmail.env.action === "compose") {
      rcmail.addEventListener("change_identity", function() {
        sessionStorage.clear();
        this.passphrase = "";
      });
      // Disable draft autosave and prompt user when saving plaintext message as draft
      rcmail.env.draft_autosave = 0;
      rcmail.addEventListener("beforesavedraft", function() {
        if($("#openpgpjs_encrypt").is(":checked")) {
          if(!confirm(rcmail.gettext("save_draft_confirm", "rc_openpgpjs"))) {
            return false;
          }
        }

        return true;
      });

      rcmail.env.compose_commands.push("open-key-manager");
      rcmail.addEventListener("beforesend", function(e) {
        return beforeSend();
      });
    } else if(rcmail.env.action === "show" || rcmail.env.action === "preview") {
      processReceived();
    }
  });

  /**
   * Processes received messages
   */
  function processReceived() {
    var msgbody = $("#messagebody div.message-part pre");

    // This function is called by set_passphrase, but there are situations
    // where set_passphrase is called where we are not trying to read a
    // message.  Namely, when we are trying to sign a message, we also need to
    // decrypt the private key, even though there is no message we're trying to
    // decrypt.
    // If we find that there is no messagebody on the screen, just quit.
    if (msgbody.length == 0) {
      return;
    }

    var msg = rc_openpgpjs_crypto.parseMsg(msgbody.html());

    // OpenPGP failed parsing the message, no action required.
    if(!msg) {
      return;
    }

    // msg[0].type: 2 == signed only
    // msg[0].type: 3 == encrypted only

    showKeyInfo(msg);

    if(msg[0].type === 2) {
      // rcmail.env.sender contains "Jon Doe <jd@example.com>" or just "jd@example.com";
      // We try to extract the email address (according to RFC 5322) in either case
      var senderAddress = rcmail.env.sender.match(/[A-Za-z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+/);
      if(!senderAddress || !senderAddress.length) {
        // In the case of a bogus sender name/address, throw an error
        displayUserMessage(rcmail.gettext('signature_invalid_sender', 'rc_openpgpjs'), 'notice');
        return false;
      }
      senderAddress = senderAddress[0];
      var pubkeys = rc_openpgpjs_crypto.getPubkeyForAddress(senderAddress);
      if(!pubkeys.length) {
        displayUserMessage(rcmail.gettext('signature_invalid_no_pubkey', 'rc_openpgpjs') + senderAddress, 'notice');
        return false;
      }
      if(rc_openpgpjs_crypto.verify(msg, pubkeys)) {
        displayUserMessage(rcmail.gettext('signature_valid', 'rc_openpgpjs') + ': ' + senderAddress, 'confirmation');
        $("#messagebody div.message-part pre").html("<strong>********* *BEGIN SIGNED PART* *********</strong>\n" + escapeHtml(msg[0].text) + "\n<strong>********** *END SIGNED PART* **********</strong>");
        return true;
      } else {
        displayUserMessage(rcmail.gettext('signature_invalid', 'rc_openpgpjs'), 'error');
        return false;
      }
    }

    if(!rc_openpgpjs_crypto.getPrivkeyCount()) {
      rcmail.display_message(rcmail.gettext("no_key_imported", "rc_openpgpjs"), "error");
      return false;
    }

    if((typeof this.passphrase == "undefined" || this.passphrase === "") && rc_openpgpjs_crypto.getPrivkeyCount() > 0) {
      $("#openpgpjs_key_select").dialog("open");
      return false;
    }

    // json string from set_passphrase, obj.id = privkey id, obj.passphrase = privkey passphrase
    var passobj = this.passphrase;
    var privkey_armored = rc_openpgpjs_crypto.getPrivkeyArmored(passobj.id);

    decrypted = rc_openpgpjs_crypto.decrypt(msg, privkey_armored, passobj.passphrase);
    if(decrypted) {
      $("#messagebody div.message-part pre").html("<strong>********* *BEGIN ENCRYPTED or SIGNED PART* *********</strong>\n" + escapeHtml(decrypted) + "\n<strong>********** *END ENCRYPTED or SIGNED PART* **********</strong>");
    } else {
      alert("This message was not meant for the private key that you are using.");
    }

    return true;
  }

  /**
   * Extracts public key info from parsed OpenPGP message.
   *
   * @param string Parsed OpenPGP message
   */
  function showKeyInfo(msg) {
    var sender = rcmail.env.sender.match(/[a-zA-Z0-9\._%+-]+@[a-zA-Z0-9\._%+-]+\.[a-zA-Z]{2,4}/g)[0];

    try {
      var fingerprint = rc_openpgpjs_crypto.getFingerprintForSender(sender);
    } catch(e) {
      return false;
    }

    if(typeof(this.getinfo) === "undefined") {
      $(".headers-table").css( "float", "left" );
      $(".headers-table").after("<div id=\"openpgpjs_info\"><table><tbody></tbody></table></div>");

      // Carefully escape anything that is appended to the info table, otherwise
      // anyone clever enough to write arbitrary data to their pubkey has a clear
      // exploitation path.
      $("#openpgpjs_info table tbody").append("<tr><td>Key algo:</td><td>" + typeToStr(msg[0].type) + "</td></tr>");
      $("#openpgpjs_info table tbody").append("<tr><td>Created:</td><td>" + escapeHtml(String(msg[0].messagePacket.creationTime))  + "</td></tr>");
      $("#openpgpjs_info table tbody").append("<tr><td>Fingerprint:</td><td>" + fingerprint + "</td></tr>");
      this.getinfo = false;
    }
  }

  /**
   * Generates an OpenPGP key pair by calling the necessary crypto
   * functions from openpgp.js and shows them to the user
   *
   * @param bits {Integer} Number of bits for the key creation
   * @param algo {Integer} To indicate what type of key to make. RSA is 1
   */
  function generate_keypair(bits, algo) {
    if($("#gen_passphrase").val() === "") {
      $("#generate_key_error").removeClass("hidden");
      $("#generate_key_error p").html(rcmail.gettext("enter_pass", "rc_openpgpjs"));
      return false;
    } else if($("#gen_passphrase").val() !== $("#gen_passphrase_verify").val()) {
      $("#generate_key_error").removeClass("hidden");
      $("#generate_key_error p").html(rcmail.gettext("pass_mismatch", "rc_openpgpjs"));
      return false;
    }

    // TODO Currently only RSA is supported, fix this when OpenPGP.js implements ElGamal & DSA
    var identities = JSON.parse($("#openpgpjs_identities").html());
    var selectedIdent = $("#gen_ident option:selected").val();
    var keys = rc_openpgpjs_crypto.generateKeys(bits, identities[selectedIdent], $("#gen_passphrase").val()).then(
    function (result) {
      $("#generated_keys").html("<pre id=\"generated_private\">" + result.privateKeyArmored + "</pre><pre id=\"generated_public\">" + result.publicKeyArmored  +  "</pre>");
      $("#generate_key_error").addClass("hidden");
      $("#import_button").removeClass("hidden");
    },
    function (err) {
      $("#generate_key_error p").html(err);
      $("#generate_key_error").removeClass("hidden");
    });

    return true;
  }
  window.generate_keypair = generate_keypair;
  

  /**
   * Import generated key pair.
   */
  function importGenerated() {
    $("#import_button").addClass("hidden");

    if (importPrivKey($("#generated_private").html(), '#generate_key_error')
        && importPubKey($("#generated_public").html(), "#generate_key_error"))
    {
      $("#gen_passphrase").val("");
      $("#gen_passphrase_verify").val("");
      alert(rcmail.gettext("import_gen", "rc_openpgpjs"));
    }
  }
  window.importGenerated = importGenerated;

  /**
   * Set passphrase.
   * This will be called by the #openpgpjs_key_select dialog.
   *
   * @param i {Integer} Used as this.keyring.[private|public]Keys.keys[i]
   * @param p {String}  The passphrase
   */
  // TODO: move passphrase checks from old decrypt() to here
  function set_passphrase(i, p) {
    if(i === "-1") {
      $("#key_select_error").removeClass("hidden");
      $("#key_select_error p").html(rcmail.gettext("select_key", "rc_openpgpjs"));
      this.key_select_resolve_reject.reject();
    }

    rc_openpgpjs_crypto.decryptSecretKey(i, p)
    .then(function (decryptedKey) {
      var selected_key = { "id" : i, "passphrase" : p };

      // We may have been entering a passphrase because we were attempting to
      // read an encrypted message, and we needed the private key in order to do
      // that.  In that case, we will want to process the message now.
      // XXX I have not examined this flow yet.  It probably doesn't work, and it
      // will probably change.
      processReceived();

      if($("#openpgpjs_rememberpass").is(":checked")) {
        sessionStorage.setItem(i, this.passphrase);
      }

      this.key_selected = true;
      $("#key_select_error").addClass("hidden");
      $("#openpgpjs_key_select").dialog("close");

      this.key_select_resolve_reject.resolve(selected_key);
    },
    function (decryptFailedReason) {
      $("#key_select_error").removeClass("hidden");
      $("#key_select_error p").text(rcmail.gettext("incorrect_pass", "rc_openpgpjs"));
    });
  }
  window.set_passphrase = set_passphrase;

  function fetchRecipientPubkeys() {
    var pubkeys = new Array();

    var c = 0;
    var recipients = [];
    var matches = "";
    var fields = ["_to", "_cc", "_bcc"];
    var re = /[a-zA-Z0-9\._%+-]+@[a-zA-Z0-9\._%+-]+/g;

    for(field in fields) {
      matches = $("#" + fields[field]).val().match(re);

      for(var i in matches) {
        recipients[c] = matches[i];
        c++;
      }
    }

    for (var i = 0; i < recipients.length; i++) {
      var recipient = recipients[i];
      var pubkey = rc_openpgpjs_crypto.getPubkeyForAddress(recipient);
      // XXX If we find more than one pubkey, we should let the user choose.
      if(typeof(pubkey[0]) != "undefined") {
        pubkeys.push(pubkey[0]);
      } else {
        // Querying PKS for recipient pubkey
       if(confirm(rcmail.gettext("missing_recipient_pubkey", "rc_openpgpjs") + recipient)) {
          rcmail.http_post("plugin.pks_search", "search=" + recipient + "&op=index");
          $("#openpgpjs_search_input").attr("disabled", "disabled");
          $("#openpgpjs_search_submit").attr("disabled", "disabled");
          $("#openpgpjs_key_search").dialog("open");
        }
        return false;
      }
    }

    return pubkeys;
  }

  function fetchSendersEmail() {
    var identities = JSON.parse($("#openpgpjs_identities").text());
    var identity_id = $("#_from>option:selected").val();
    var identity = $.grep(identities, function (e) { return e.identity_id == identity_id; })[0];
    if (typeof identity == "undefined") {
      return undefined;
    }

    var address = identity.email;
    
    return address;
  }

  /**
   * Get the user's public key
   */
  function fetchSendersPubkey() {
    var address = fetchSendersEmail();
    
    var pubkeys = rc_openpgpjs_crypto.getPubkeyForAddress(address);

    // XXX If we find more than one key, we should give the user the choice of which to use!
    return pubkeys[0];
  }

  /**
   * send the user's public key to the server so it can be sent as attachment
   * @return Promise<String> The filename of the attachment on the server.  
   *                         The filename will be null if the user has no pubkey.
   */
  function sendPubkey() {
    var pubkey_save_promise;
    
    var pubkey_sender = fetchSendersPubkey();
    if (pubkey_sender) {
      // Create a Promise which will only be resolved when the rcmail.http_post completes.
      // We can then do pubkey_save_callback_promise.then() to wait for the http_post to complete.
      pubkey_save_promise = new Promise(function (resolve, reject) {
        this.pubkey_save_resolve = resolve;
      });

      var lock = rcmail.set_busy(true, 'loading');
      rcmail.http_post('plugin.pubkey_save', { _pubkey: pubkey_sender.armor() }, lock);
    } else {
      // We are not sending the user's pubkey to the server because the user has no pubkey.
      pubkey_save_promise = Promise.resolve(null);
    }

    return pubkey_save_promise;
  }


  /**
   * Processes messages before sending
   */
  function beforeSend() {
    // As much as I'd like to simply let exceptions bubble up and out (I
    // would like that very much), it is IMPERATIVE!! that we return false
    // if anything goes wrong.
    // The "command" function in app.js requires "before" hooks to
    // affirmatively return false in order to cancel the send.  If they
    // simply don't return anything, then the command will go through.
    // See app.js:729 of roundcube 1.3.4.
    //
    // If something throws an exception in beforeSend, then it will fail to
    // return false.
    // That means that we maybe didn't encrypt a message that the user
    // intended to encrypt.  If that "send" command goes through, the
    // plaintext will be sent, when the user intended to send encrypted
    // text.  This can literally get people killed in real life.
    // 
    // I have an idea:  Before attempting to do anything (even before
    // checking if the "encrypt" box was checked), pull all the text out of
    // the text area, set it aside in some other variable, and then clear
    // the text area itself.  That way, if an exception is thrown and the
    // send accidentally goes through, it just sends a blank message.  If
    // we do it that way, we don't have to do this try/catch here; we can
    // allow the exceptions to bubble up and out.  This is desirable
    // because it makes debugging easier, and even lets the user know that
    // something went wrong.

    // This idea seems to be working.
    // HOWEVER, I'm not totally satisfied with this.  It may cause the user to
    // send a blank message when they intended to send the *encrypted version of*
    // a blank message, which would not actually be blank.
    // Instead of blank, I could put some placeholder text in there, but it's
    // probably best not to try to think of something sufficiently neutral.  If
    // the placeholder text is actually sent, we will have leaked some
    // information, such as: the fact that we intended to use encryption; what
    // software we are using; the fact that an error occurred; the fact that
    // messages get sent if errors occur.
    // If we had succeeded in encrypting the message, the eavesdropper would
    // also know that we intended to use encryption.  But I don't want to
    // assume that it's ok to leak that info if there's a failure.  If there's
    // a failure, the most correct way to behave is to not send anything.
    if (this.cleartext == null) {
      this.cleartext = $("textarea#composebody").val();
      $("textarea#composebody").val("");
    }

    // If we're finished with everything, and the ciphertext is computed, put
    // it back in there and allow the send to go through.
    console.log("FINished treating???", this.finished_treating);
    if (this.finished_treating) {
      this.cleartext = null;
      $("textarea#composebody").val(this.ciphertext);
      return true;
    }


    if( !$("#openpgpjs_encrypt").is(":checked") &&
        !$("#openpgpjs_sign").is(":checked")) {

         if ($("#openpgpjs_warn").val() == "1" ) {
            if(confirm(rcmail.gettext("continue_unencrypted", "rc_openpgpjs"))) {
                // The user intends to send cleartext.  
                // It is thus safe to replace the cleartext back into the textarea.
                $("textarea#composebody").val(this.cleartext);

                // remove the public key attachment since we don't sign nor encrypt the message
                removePublicKeyAttachment();
                return true;
            } else {
                return false;
            }
         }
         else
         {
             // The user intends to send cleartext.  
             // It is thus safe to replace the cleartext back into the textarea.
             $("textarea#composebody").val(this.cleartext);
             return true
         }
    }

    // This will be a Promise to send the pubkey to the server.
    // We will set this when we've decided to actually encrypt/sign the message.
    // We may decide not to send the message if, for example, the recipient has
    // no public key, we have no private key, or we can't decrypt the private
    // key.
    // Note that sendPubkey may return null if it declines to save the pubkey.
    // We will set this to null here so that if we decline to attempt to save
    // the pubkey, we'll get the same result: null.
    var pubkey_save_promise = null;

    // This will be a Promise to encrypt (and/or sign) the message.
    // We will set it when we know which operations we are actually doing (enc/sign).
    var enc_sign_promise;

    // This is a roundcube "lock".  We will set it when we set_busy to start encryption/signing.
    // We don't set it now because if we are signing, then we'll have to get a
    // password to unlock the private key.  Maybe the user cancels at that
    // point.
    var enc_lock = rcmail.set_busy(true, 'encrypting');

    // Encrypt and sign
    if($("#openpgpjs_encrypt").is(":checked") && $("#openpgpjs_sign").is(":checked")) {
      // get the private key
      if((typeof this.passphrase == "undefined" || this.passphrase === "") && rc_openpgpjs_crypto.getPrivkeyCount() > 0) {
        this.passphrase_state = "pending"; // Global var to notify set_passphrase
        $("#openpgpjs_key_select").dialog("open");
        return false;
      }

      if(!rc_openpgpjs_crypto.getPrivkeyCount()) {
        alert(rcmail.gettext("no_keys", "rc_openpgpjs"));
        return false;
      }

      var passobj = this.passphrase;
      var privkey = rc_openpgpjs_crypto.getPrivkeyObj(passobj.id);

      if(!privkey[0].decryptSecretMPIs(passobj.passphrase)) {
        alert(rcmail.gettext("incorrect_pass", "rc_openpgpjs"));
      }
      // we now have the private key (for signing)
      
      // get the public key
      var pubkeys = fetchRecipientPubkeys();
      if(pubkeys.length === 0) {
        return false;
      }
      // done public keys

      // add the user's public key
      var pubkey_sender = fetchSendersPubkey();
      if (pubkey_sender) {
        pubkeys.push(pubkey_sender);
      } else {
        if (!confirm("Couldn't find your public key. You will not be able to decrypt this message. Continue?")) {
          return false;
        }
      }
      // end add user's public key

      var encrypted = rc_openpgpjs_crypto.encrypt(pubkeys, this.cleartext, 1, privkey, passobj.passphrase);
                
      if(encrypted) {
        $("textarea#composebody").val(encrypted);
        this.finished_treating = true;
        return true;
      }
    }

    // Encrypt only
    if($("#openpgpjs_encrypt").is(":checked")
       && !$("#openpgpjs_sign").is(":checked"))
    {
      // Fetch recipient pubkeys
      var pubkeys = fetchRecipientPubkeys();
      if(pubkeys.length === 0) {
        // XXX We should notify the user that we've given up!
        return false;
      }
      
      // add the user's public key
      var pubkey_sender = fetchSendersPubkey();
      if (pubkey_sender) {
        pubkeys.push(pubkey_sender);
      } else {
        if (!confirm("Couldn't find your public key. You will not be able to decrypt this message. Continue?")) {
          return false;
        }
      }
      // end add user's public key

      pubkey_save_promise = sendPubkey();
      
      enc_sign_promise = rc_openpgpjs_crypto.encrypt(pubkeys, this.cleartext);
    }

    // Sign only
    if($("#openpgpjs_sign").is(":checked") &&
       !$("#openpgpjs_encrypt").is(":checked")) {

      if(!rc_openpgpjs_crypto.getPrivkeyCount()) {
        alert(rcmail.gettext("no_keys", "rc_openpgpjs"));
        return false;
      }

      // We can only start encryption once the user has entered the passphrase.
      // We will also not start sending the pubkey until that time.
      // However, right away, we must have a pubkey_save_promise and an
      // enc_sign_promise so that we can wait for them.
      // Therefore, we create our own Promises that we will resolve when we
      // have the passphrase.
      var pubkey_save_resolve_reject;
      var enc_sign_resolve_reject;
      pubkey_save_promise = new Promise(function (resolve, reject) {
        pubkey_save_resolve_reject = { resolve: resolve, reject: reject };
      });

      enc_sign_promise = new Promise(function (resolve, reject) {
        enc_sign_resolve_reject = { resolve: resolve, reject: reject };
      });

      // Open the dialog to choose a key.
      // We construct a Promise that will be resolved when the user has chosen
      // a key and entered a passphrase.  The key_select_resolve_reject global
      // var will be used by the dialog's close function, to return control
      // back here.
      new Promise(function (resolve, reject) {
        $("#openpgpjs_key_select").dialog("open");
        this.key_select_resolve_reject = {resolve: resolve, reject: reject};
      }).then(function (selected_key) { // If the key select turned out ok.
        // Now that they've chosen a key to sign with, we can save the sender's
        // pubkey to the server.  We hadn't started this process before because
        // we didn't know if the user would cancel instead of choosing a
        // signing key.
        // XXX I notice that the key they chose to sign with is not necessarily
        // the same one that we're sending here.  We're sending the first
        // pubkey associated with the sender's email address, whereas they
        // could be signing with any private key they have.  We may want to
        // send both pubkeys.
        sendPubkey().then(function (pubkey_filename) {
          pubkey_save_resolve_reject.resolve(pubkey_filename);
        });

        var privkey = rc_openpgpjs_crypto.getPrivkeyObj(selected_key.id);

        rc_openpgpjs_crypto.sign(this.cleartext, privkey, selected_key.passphrase).then(function (signed) {
          enc_sign_resolve_reject.resolve(signed);
        });
      },
      function (key_select_failed_reason) { // If the user cancelled the key select.
        enc_sign_resolve_reject.reject(key_select_failed_reason);
        rcmail.set_busy(false, null, enc_lock);
        $("textarea#composebody").val(window.cleartext);
        this.cleartext = null;
      });
    }

    // Wait for all the operations to complete.
    Promise.all([pubkey_save_promise, enc_sign_promise]).then(function ([pubkey_filename, encrypted]) {
      rcmail.set_busy(false, null, enc_lock);
      this.ciphertext = encrypted.data;

      // set a global var and call command send again
      this.finished_treating = true;
      rcmail.command("send", this);
    },
    function (failed_reason) {
      // This should only happen if the user cancelled the key select, because
      // this is only reached if an affirmative reject is called.  If an
      // exception is thrown, control does not reach this.
      // Still, replacing the text in the box happens closer to the time when
      // we're sure the user affirmatively cancelled.  But we must have a
      // handler here to handle the case where the promise is rejected.  If we
      // don't, then the affirmative cancellation will bubble up and become an
      // exception.  Instead, we should just quietly stop.
    });

    // Block the send until our encryption tasks are done.
    return false;
  }

  /**
   * Removes the public key attachment
   * Used if the user doesn't sign nor encrypt the message
   */
  function removePublicKeyAttachment() {
    $("#attachment-list").each(function() {
      $(this).find('li').each(function() {
        if ($(this).text().indexOf('pubkey.asc') >= 0) {
          rcmail.command('remove-attachment', $(this).attr('id'));
          return false;
        }
      });
    });
  }

  function importFromSKS(id) {
    rcmail.http_post("plugin.pks_search", "search=" + id + "&op=get");
    return;
  }
  window.importFromSKS=importFromSKS;

  /**
   * Imports armored public key into the key manager
   *
   * @param key {String} The armored public key
   * @param err_div_id {String} A jquery selector; this is where to put any error text.
   * @return {Bool} Import successful
   */
  function importPubKey(key, err_div_id) {
    if (typeof err_div_id == "undefined") { err_div_id = "#import_pub_error"; }

    try {
      rc_openpgpjs_crypto.importPubkey(key);
      updateKeyManager();
      $("#importPubkeyField").val("");
      $(err_div_id).addClass("hidden");
    } catch(e) {
      $(err_div_id).removeClass("hidden");
      $(err_div_id+" p").html(rcmail.gettext("import_failed", "rc_openpgpjs"));
      $(err_div_id+" p").append("<ul></ul>");
      $(e).each(function (num, err) { $(err_div_id+" p ul").append("<li>"+err+"</li>"); });

      return false;
    }

    return true;
  }
  window.importPubKey = importPubKey;

  /**
   * op: (get|index|vindex) string operation to perform
   * search: string phrase to pass to HKP
   *
   * To retrieve all matching keys: pubkey_search("foo@bar", "index")
   * To retrieve armored key of specific id: pubkey_search("0xF00", "get")
   *
   * If op is get then search should be either 32-bit or 64-bit. See
   * http://tools.ietf.org/html/draft-shaw-openpgp-hkp-00#section-3.1.1.1
   * for more details.
   *
   */
  // TODO: Version 3 fingerprint search
  function pubkey_search(search, op) {
    if(search.length === 0) {
      return false;
    }

    rcmail.http_post("plugin.pks_search", "search=" + search + "&op=" + op);
    return true;
  }

  function pubkey_save_callback({unlock: unlock, file: file}) {
    rcmail.set_busy(false, null, unlock);
    // The beforeSend function is waiting for a Promise to be resolved.  That
    // Promise can be resolved by calling this.pubkey_save_resolve.

    // XXX We probably have to do something in order to actually attach the
    // pubkey; so far, we've just transmitted the data into a tempfile on the
    // server.
    this.pubkey_save_resolve(file);
    this.pubkey_save_resolve = null;
  }

  function pks_search_callback(response) {
    $("#openpgpjs_search_input").removeAttr("disabled");
    $("#openpgpjs_search_submit").removeAttr("disabled");

    if (response.status != 200) {
      // See if it's one of the errors we know.
      // If it is, that gives us the opportunity to display a localized version
      // of the error message, along with the original.

      var result;
      try {
        result = JSON.parse(response.message);
      } catch(e) {
        const full_errmsg = rcmail.gettext("unknown_error", "rc_openpgpjs")+"\n"+response.message;
        alert(full_errmsg);
        return false;
      }

      var errmsg;
      if (result.title == "No results found") {
        errmsg = rcmail.gettext("search_no_keys", "rc_openpgpjs");
      } else {
        errmsg = rcmail.gettext("unknown_error", "rc_openpgpjs");
      }
        
      const full_errmsg = errmsg+"\n"
                          + rcmail.gettext("server_said", "rc_openpgpjs")+"\n"
                          + response.status+"\n"
                          + result.title+"\n"
                          + result.body;

      alert(full_errmsg);
      return false;
    }

    if(response.op === "index") {
      var errmsg;
      try {
        result = JSON.parse(response.message);
      } catch(e) {
        const full_errmsg = rcmail.gettext("unknown_error", "rc_openpgpjs")+"\n"+response.message;
        alert(full_errmsg);
        return false;
      }

      // We haven't included the assert library, but I'm leaving this here as documentation.
      // assert.equal(typeof result, "array");
      // assert(result.length > 0);

      $("#openpgpjs_search_results").html("");
      for(var i = 0; i < result.length; i++) {
        $("#openpgpjs_search_results").append("<tr class='" + (i%2 !== 0 ? " odd" : "") + "'><td><a href='#' onclick='importFromSKS(\"" + result[i].key_id + "\");'>Import</a></td><td class=\"result-txt\"><pre></pre></td></tr>");
        $("#openpgpjs_search_results tr:last td.result-txt pre").text(result[i].text);
      }
    } else if(response.op === "get") {
      k = JSON.parse(response.message);
      $("#importPubkeyField").val(k[0]);
      if(importPubKey($("#importPubkeyField").val())) {
        alert(rcmail.gettext("pubkey_import_success", "rc_openpgpjs"));
      }
    }
  }

  /**
   * Imports armored private key into the key manager
   *
   * @param key        {String} The armored private key
   * @param passphrase {String} The corresponding passphrase
   * @return {Bool} Import successful
   */
  function importPrivKey(key, err_div_id) {
    if (typeof err_div_id == "undefined") { err_div_id = '#import_priv_error'; }

    try {
      rc_openpgpjs_crypto.importPrivkey(key);
    } catch(e) {
      $(err_div_id).removeClass("hidden");
      $(err_div_id+" p").html(rcmail.gettext("import_failed", "rc_openpgpjs"));
      $(err_div_id+" p").append("<ul></ul>");
      $(e).each(function (num, err) { $(err_div_id+" p ul").append("<li>"+err+"</li>"); });
      return false;
    }

    updateKeyManager();
    $("#importPrivkeyField").val("");
    $(err_div_id).addClass("hidden");

    return true;
  }
  window.importPrivKey = importPrivKey;

  /**
   * Select a private key.
   *
   * @param i {Integer} Used as openpgp.keyring[private|public]Keys[i]
   */
  function select_key(i) {
    fingerprint = rc_openpgpjs_crypto.getFingerprint(i, true, false);
    $("#openpgpjs_selected").html("<strong>" + rcmail.gettext("selected", "rc_openpgpjs") + ":</strong> " + $(".clickme#" + fingerprint).html());
    $("#openpgpjs_selected_id").val(i);
    $("#passphrase").val("");
  }
  window.select_key = select_key;

  /**
   * Update key selector dialog.
   */
  function updateKeySelector() {
    // Fills key_select key list
    $("#openpgpjs_key_select_list").html("<input type=\"hidden\" id=\"openpgpjs_selected_id\" value=\"-1\" />");

    // Only one key in keyring, nothing to select from
    if(rc_openpgpjs_crypto.getPrivkeyCount() === 1) {
      $("#openpgpjs_selected_id").val(0);
    } else {
      // Selected set as $("#openpgpjs_selected_id").val(), then get that value from set_passphrase
      for (var i = 0; i < rc_openpgpjs_crypto.getPrivkeyCount(); i++) {
        var persons = rc_openpgpjs_crypto.getPersons(i, true);
        for (var j = 0; j < persons.length; j++) {
          fingerprint = rc_openpgpjs_crypto.getFingerprint(i, true, false);
          person = persons[j];
          $("#openpgpjs_key_select_list").append("<div class=\"clickme\" id=\"" + fingerprint +"\" onclick=\"select_key(" + i + ");\"></div>");
          $("#openpgpjs_key_select_list #"+fingerprint).text(fingerprint+" "+person);
        }
      }

      $("#openpgpjs_key_select_list").append("<div id=\"openpgpjs_selected\"><strong>" + rcmail.gettext("selected", "rc_openpgpjs") + ":</strong> <i>" + rcmail.gettext("none", "rc_openpgpjs") + "</i></div>");
    }

    return true;
  }

  /**
   * Fill key manager public/private key table
   * @param usePrivate {Boolean} Should we fill the private table? If not, we fill the public table.
   */
  function fillTable(usePrivate) {
    const usePublic = !usePrivate;

    var getKeyCount = (usePrivate)? rc_openpgpjs_crypto.getPrivkeyCount.bind(rc_openpgpjs_crypto)
                                   : rc_openpgpjs_crypto.getPubkeyCount.bind(rc_openpgpjs_crypto);

    const tableId = (usePrivate)? "#openpgpjs_privkeys" : "#openpgpjs_pubkeys";
    $(tableId + " tbody").empty();

    for (var i = 0; i < getKeyCount(); i++) {
      var key_id = rc_openpgpjs_crypto.getKeyID(i, usePrivate);
      var fingerprint = rc_openpgpjs_crypto.getFingerprint(i, usePrivate);
      var persons = rc_openpgpjs_crypto.getPersons(i, usePrivate);
      var length_alg = rc_openpgpjs_crypto.getAlgorithmString(i, usePrivate);
      var statusMark;
      var status;
      if (usePublic) {
        statusMark = rc_openpgpjs_crypto.verifyBasicSignatures(i);
        // The most concise way to put this would be to say
        //   status = rcmail.gettext(statusMark, "rc_openpgpjs");
        // However, in GNU Gettext, it is a bad idea to use a variable ast the
        // gettext text, because there are automated tools that look for all the
        // labels mentioned in the code, and make files for translators to work
        // with.  If you use anything other than a string literal, it breaks that
        // workflow for translators.
        // I don't know if roundcube's home-grown gettext has similar tools, but
        // I figured it'd be best to play it safe.
        switch (statusMark) {
        case 'expired': status = rcmail.gettext("expired", "rc_openpgpjs"); break;
        case 'revoked': status = rcmail.gettext("revoked", "rc_openpgpjs"); break;
        case 'valid': status = rcmail.gettext("valid", "rc_openpgpjs"); break;
        case 'no_self_cert': status = rcmail.gettext("no_self_cert", "rc_openpgpjs"); break;
        case 'invalid':
        default: status = rcmail.gettext("invalid", "rc_openpgpjs"); break;
        }
      }

      var keyRemoveConfirmer = function (i, usePrivate) {
        return function () {
          var confirmed = false;
          var confirmText = (usePrivate)? rcmail.gettext('delete_priv', 'rc_openpgpjs')
                                        : rcmail.gettext('delete_pub', 'rc_openpgpjs');

          if (confirm(confirmText, 'rc_openpgpjs')) {
            if (rc_openpgpjs_crypto.removeKey(i, usePrivate) === null) {
              throw("Failed to delete the key "+key_id);
            } else {
              updateKeyManager();
            }
          }
        };
      };
      var del = "<a href=\"#\" class=\"del_key\">" + rcmail.gettext('delete', 'rc_openpgpjs') + "</a>";
      var export_filename_prefix = (usePrivate)? "privkey_" : "pubkey_";
      var exp = "<a href=\"data:asc," + encodeURIComponent(rc_openpgpjs_crypto.exportArmored(i, usePrivate)) + "\" download=\"" + export_filename_prefix + key_id + ".asc\">Export</a> ";

      var result = "<tr>" +
        "<td>" + key_id      + "</td>" +
        "<td>" + fingerprint + "</td>" +
        "<td class=\"person\"><ul></ul></td>" +
        "<td>" + length_alg  + "</td>" +
        ((usePublic)? ("<td>" + status      + "</td>") : "") +
        "<td class=\"actions\">" + exp + del   + "</td>" +
        "</tr>";

      $(tableId + " tbody").append(result);
      // Set "person" using the text property to get html escaped.
      persons.forEach(function (person) { 
        $(tableId + " tbody tr:last td.person ul").append('<li></li>');
        $(tableId + " tbody tr:last td.person ul li:last").text(person);
      });
      $(tableId + " tbody tr:last td.actions a.del_key").click(keyRemoveConfirmer(i, usePrivate));
    }
  }

  /**
   * Updates key manager public keys table, private keys table
   * and identy selector.
   */
  function updateKeyManager() {
    // Fill the key manager public key table.
    fillTable(false);

    // Fill the key manager private key table.
    fillTable(true);

/*
    // fill key manager private key table
    $("#openpgpjs_privkeys tbody").empty();
    for (var i = 0; i < rc_openpgpjs_crypto.getPrivkeyCount(); i++) {
      for (var j = 0; j < rc_openpgpjs_crypto.getKeyUserids(i, true).length; j++) {
        var key_id = rc_openpgpjs_crypto.getKeyID(i, true);
        var fingerprint = rc_openpgpjs_crypto.getFingerprint(i, true);
        var person = rc_openpgpjs_crypto.getPerson(i, j, true);
        var length_alg = rc_openpgpjs_crypto.getAlgorithmString(i, true);
        var del = "<a href='#' onclick='if(confirm(\"" + rcmail.gettext('delete_priv', 'rc_openpgpjs') + "\")) { rc_openpgpjs_crypto.removeKey(" + i + ", true); updateKeyManager(); }'>" + rcmail.gettext('delete', 'rc_openpgpjs') + "</a>";
        var exp = "<a href=\"data:asc," + encodeURIComponent(rc_openpgpjs_crypto.exportArmored(i, true)) + "\" download=\"privkey_" + rc_openpgpjs_crypto.getKeyID(i, true) + ".asc\">Export</a> ";

        var result = "<tr>" +
          "<td>" + key_id      + "</td>" +
          "<td>" + fingerprint + "</td>" +
          "<td class=\"person\"></td>" +
          "<td>" + length_alg  + "</td>" +
          "<td>" + exp + del   + "</td>" +
          "</tr>";

        $("#openpgpjs_privkeys tbody").append(result);
        // We add the "person" thing using the text property so that any unsafe html gets escaped.
        $("#openpgpjs_privkeys tbody tr:last td.person").text(person);
      }
    }
*/

    // fill key manager generation identity selector
    $("#gen_ident").html("");
    identities = JSON.parse($("#openpgpjs_identities").html());
    for (var i = 0; i < identities.length; i++) {
      var identStr = identities[i].name + " <" + identities[i].email + ">";
      $("#gen_ident").append("<option value='" + i + "'></option>");
      // we use the text property so that html gets escaped.
      $("#gen_ident option:last").text(identStr);
    }
  }

  /**
   * Converts an algorithm id (1/2/3/16/17) to the
   * corresponding algorithm type
   *
   * @param id {Integer} Algorithm id
   * @return {String} Algorithm type
   */
  function typeToStr(id) {
    var r = ""

    switch(id) {
      case 1:
        r = "RSA(S/E)";
        break;
      case 2:
        r = "RSA(E)";
        break;
      case 3:
        r = "RSA(S)";
        break;
      case 16:
        r = "Elg";
        break;
      case 17:
        r = "DSA";
        break;
      default:
        r = "UNKNOWN";
        break;
    }

    return(r);
  }

  function showMessages(msg) { console.log(msg); }

  /**
   * Display a custom message above the email body, analogous to
   * Roundcubes privacy warning message.
   *
   * @param msg  {String} Message to display
   * @param type {String} One of 'confirmation', 'notice', 'error'
   */
  function displayUserMessage(msg, type) {
    // Insert a div into the message-objects <div> provided by Roundcube
    $('<div>').text(msg).addClass(type).addClass('messagepadding').appendTo($('#message-objects'));
  }
}
