/*
 * +-------------------------------------------------------------------------+
 * | OpenPGP.js implemented in Roundcube. This file covers the cryptographic |
 * | functionalities.                                                        |
 * |                                                                         |
 * | Copyright (C) 2013 Niklas Femerstrand <nik@qnrq.se>                     |
 * |                                                                         |
 * | This program is free software; you can redistribute it and/or modify    |
 * | it under the terms of the GNU General Public License version 2          |
 * | as published by the Free Software Foundation.                           |
 * |                                                                         |
 * | This program is distributed in the hope that it will be useful,         |
 * | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
 * | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
 * | GNU General Public License for more details.                            |
 * |                                                                         |
 * | You should have received a copy of the GNU General Public License along |
 * | with this program; if not, write to the Free Software Foundation, Inc., |
 * | 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.             |
 * |                                                                         |
 * +-------------------------------------------------------------------------+
 * */

const openpgp = require('openpgp');
// openpgp.init();
// openpgp.config.debug = true

function rc_openpgpjs_crypto () {
  this.keyring = new openpgp.Keyring();
};

/**
 * Encrypt (and sign) a message
 *
 * @param pubkeys {Array}  Public keys
 * @param text    {String} Message to encrypt
 * @param sign    {Bool}   Sign and encrypt the message?
 * @param decryptedPrivkey {openpgp.Key} If signing, this key must already be decrypted.
 * @return {Promise<Object>} encrypted (and optionally signed message) in the form:
 *                           {data: ASCII armored message}

 */
// TODO: Feed key armored and do openpgp.read_* here
rc_openpgpjs_crypto.prototype.encrypt = function (pubkeys, text, sign, decryptedPrivkey) {
  if (sign) {
    return openpgp.encrypt({
      data: new String(text),
      publicKeys: pubkeys,
      privateKeys: decryptedPrivkey.key
    });
  } else {
    return openpgp.encrypt({
      data: new String(text),
      publicKeys: pubkeys
    });
  }
}

/**
 * Generates key pair
 *
 * @param bits       {Integer} Key length in bits
 * @param ident      {String}  Ident object {name: 'Kate Exampleman', email: 'example@example.com'}
 * @param passphrase {String} Passphrase of private key
 * @return {Array} Armored key pair
 */
rc_openpgpjs_crypto.prototype.generateKeys = function (bits, ident, passphrase) {
  const userId = {name: ident.name, email: ident.email};
  return openpgp.generateKey({userIds:[userId], passphrase:passphrase, numBits:bits});
}

/**
 * Sign a message
 *
 * @param msg               {String} Message to sign
 * @param decryptedPrivkey  {Key}    Private key object to sign message with.  
                                            It must already be decrypted.
 * @return                  {Promise<Object>}  signed cleartext in the form:
 *                                             {data: ASCII armored message}
 */
rc_openpgpjs_crypto.prototype.sign = function (msg, decryptedPrivkey) {
  return openpgp.sign({
    data: new String(msg),
    privateKeys: decryptedPrivkey.key
  });
}

/**
 * Decrypt a meesage
 *
 * @param msg             {String} Message to decrypt
 * @param privkey_armored {String} Armored private key to decrypt message
 * @param passphrase      {String} Passphrase of private key
 * @return {String} Decrypted message
 */
rc_openpgpjs_crypto.prototype.decrypt = function (msg, privkey_armored, passphrase) {
  if(!("decrypt" in msg[0])) {
    return false;
  }

  var priv_key = openpgp.read_privateKey(privkey_armored);
  var keymat = null;
  var sesskey = null;

  if(!priv_key[0].decryptSecretMPIs(passphrase)) {
    alert("wrong pass");
    return false;
  }

  for (var i = 0; i< msg[0].sessionKeys.length; i++) {
    if (priv_key[0].privateKeyPacket.publicKey.getKeyId() === msg[0].sessionKeys[i].keyId.bytes) {
      keymat = { key: priv_key[0], keymaterial: priv_key[0].privateKeyPacket};
      sesskey = msg[0].sessionKeys[i];
      break;
    }

    for (var j = 0; j < priv_key[0].subKeys.length; j++) {
      if (priv_key[0].subKeys[j].publicKey.getKeyId() === msg[0].sessionKeys[i].keyId.bytes) {
        if(!priv_key[0].subKeys[j].decryptSecretMPIs(passphrase)) {
          alert("Wrong pass");
          return false;
        }
        keymat = { key: priv_key[0], keymaterial: priv_key[0].subKeys[j]};
        sesskey = msg[0].sessionKeys[i];
        break;
      }
    }
  }

  try {
    decrypted = msg[0].decrypt(keymat, sesskey);
    return decrypted;
  } catch (e) {
    return false;
  }
}


/**
 * Verify signature of a clear-text message
 *
 * @param msg     {array}  Message to verify
 * @param pubkeys {array}  Public key(s) to verify against
 */
rc_openpgpjs_crypto.prototype.verify = function (msg, pubkeys) {
  return msg[0].verifySignature(pubkeys);
}


rc_openpgpjs_crypto.prototype.parseMsg = function (msg) {
	return openpgp.read_message(msg);
}

rc_openpgpjs_crypto.prototype.hasPrivateKey = function () {
	return this.keyring.privateKeys.keys.length > 0;
}

rc_openpgpjs_crypto.prototype.getPrivkeyCount = function () {
	return this.keyring.privateKeys.keys.length;
}

rc_openpgpjs_crypto.prototype.getPubkeyCount = function () {
	return this.keyring.publicKeys.keys.length;
}

rc_openpgpjs_crypto.prototype.getFingerprint = function (i, getPrivate, niceformat) {
	if(typeof(getPrivate) == "undefined") {
		gePrivate = false;
	}

	if(typeof(niceformat) == "undefined") {
		niceformat = true;
	}

	if(getPrivate == false) {
		fingerprint = openpgp.util.hexstrdump(this.keyring.publicKeys.keys[i].primaryKey.getFingerprint());
	} else {
		fingerprint = openpgp.util.hexstrdump(this.keyring.privateKeys.keys[i].primaryKey.getFingerprint());
	}

	if(niceformat) {
		fingerprint = fingerprint.replace(/(.{2})/g, "$1 ").toUpperCase();
	} else {
		fingerprint = fingerprint;
	}

	return fingerprint;
}

rc_openpgpjs_crypto.prototype.getKeyID = function (i, getPrivate, machine_readable) {
        var key_id;

	if(getPrivate) {
	        key_id = this.keyring.privateKeys.keys[i].primaryKey.getKeyId();
	} else {
		key_id = this.keyring.publicKeys.keys[i].primaryKey.getKeyId();
	}
        
        if (machine_readable) {
          return openpgp.util.hexstrdump(key_id.bytes);
        } else {
          const key_id_str = "0x" + openpgp.util.hexstrdump(key_id.bytes).toUpperCase();
          return key_id_str;
        }
}

rc_openpgpjs_crypto.prototype.getPerson = function (i, j, getPrivate) {
	if(typeof(getPrivate) == "undefined") {
		getPrivate = false;
	}

        var person;

	if(getPrivate == false) {
		person = (this.keyring.publicKeys.keys[i].getUserIds())[j];
	} else {
		person = (this.keyring.privateKeys.keys[i].getUserIds())[j];
	}

	return person;
}

rc_openpgpjs_crypto.prototype.getPersons = function (i, getPrivate) {
	if(typeof(getPrivate) == "undefined") {
		getPrivate = false;
	}

        var persons;

	if(getPrivate == false) {
		persons = (this.keyring.publicKeys.keys[i].getUserIds());
	} else {
		persons = (this.keyring.privateKeys.keys[i].getUserIds());
	}

	return persons;
}

rc_openpgpjs_crypto.prototype.getPubkeyForAddress = function (address) {
	var pubkey = this.keyring.publicKeys.getForAddress(address);
	return pubkey;
}

rc_openpgpjs_crypto.prototype.getFingerprintForSender = function (sender) {
	var pubkey = this.getPubkeyForAddress(sender);
	var fingerprint = util.hexstrdump(pubkey[0].getFingerprint()).toUpperCase().substring(8).replace(/(.{2})/g,"$1 ");
	return fingerprint;
}

rc_openpgpjs_crypto.prototype.getPrivkeyArmored = function (id) {
	var privkey = getPrivkeyObj(id);
    return privkey.armor();
}

rc_openpgpjs_crypto.prototype.getPrivkeyObj = function (id) {
	var privkey = this.keyring.privateKeys.keys[id];
	return privkey;
}

// Gets privkey obj from armored
rc_openpgpjs_crypto.prototype.getPrivkey = function (armored) {
	var privkey = openpgp.read_privateKey(armored);
	return privkey;
}

rc_openpgpjs_crypto.prototype.decryptSecretKey = function (keyId, p) {
  const keys = this.keyring.getKeysForId(keyId, true);
  if (keys == null) {
    // If no keys match that keyId, return a pre-rejected Promise, showing that decryption failed.
    return new Promise.reject();
  } else {
    for (var i=0; i<keys.length; i++) {
      if (keys[i].isPrivate()) {
        return openpgp.decryptKey({
          privateKey: keys[i],
          passphrase: p
        });
      }
    }
  }

  // Oops, there were no secret keys matching that keyId.
  // Return a pre-rejected Promise, showing that decryption failed.
  return new Promise.reject();
}

rc_openpgpjs_crypto.prototype.decryptSecretMPIsForId = function (id, passphrase) {
	var keyid = this.keyring.privateKeys[id].getKeyId();
	var privkey_armored = this.keyring.getPrivateKeyForKeyId(keyid)[0].key.armored;
	var privkey = getPrivkey(privkey_armored);
	return privkey[0].decryptSecretMPIs(passphrase);
}

rc_openpgpjs_crypto.prototype.importPubkey = function (key) {
	try {
		this.keyring.publicKeys.importKey(key);
		this.keyring.store();
	} catch(e) {
		return false;
	}
	return true;
}

rc_openpgpjs_crypto.prototype.importPrivkey = function (key) {
	var err = this.keyring.privateKeys.importKey(key); 
        if (err !== null) {
            throw(err);
        } else {
            this.keyring.store();
        }

        // Now import the public key.
        // It's unfortunate that we have to read the key again, but I couldn't
        // think of a better way that didn't involve repeating some internal
        // logic of the library.
        var privKey = openpgp.key.readArmored(key);
        const keyring = this.keyring;
        privKey.keys.forEach(function (key) {
          var err = keyring.publicKeys.importKey(key.toPublic().armor());
          if (err !== null) {
              throw(err);
          } else {
              keyring.store();
          }
        });
        window.keyring = this.keyring;
}

rc_openpgpjs_crypto.prototype.removeKey = function (i, getPrivate) {
	if(typeof(getPrivate) == "undefined") {
		getPrivate = false;
	}

        var key_id = this.getKeyID(i, getPrivate, true);

        var ret;
	if (getPrivate) {
		ret = this.keyring.privateKeys.removeForId(key_id);
	} else {
                ret = this.keyring.publicKeys.removeForId(key_id);
        }

        if (ret !== null) {
          this.keyring.store();
        }
}

rc_openpgpjs_crypto.prototype.verifyBasicSignatures = function (i) {
        var keyStatus = this.keyring.publicKeys.keys[i].verifyPrimaryKey();
        var statusMark = 'invalid';
        for (k in openpgp.enums.keyStatus) {
            if (openpgp.enums.keyStatus[k] == keyStatus) { statusMark = k; }
        }
        return statusMark;
}

/**
 * Extract the algorithm string from a key and return the algorithm type.
 *
 * @param i {Integer} Key id in keyring
 * @return {String} Algorithm type
 */

rc_openpgpjs_crypto.prototype.getAlgorithmString = function (i, getPrivate) {
	if(typeof(getPrivate) == "undefined") {
		getPrivate = false;
	}

        var key;
	if(getPrivate) {
		key = this.keyring.privateKeys.keys[i];
	} else {
		key = this.keyring.publicKeys.keys[i];
	}

        var algo = key.primaryKey.algorithm;
        var size = key.toPublic().subKeys[0].subKey.getBitSize();

	return size+"/"+algo;
}

rc_openpgpjs_crypto.prototype.exportArmored = function (i, getPrivate) {
	if(typeof(getPrivate) == "undefined") {
		getPrivate = false;
	}

	if(getPrivate) {
		return this.keyring.privateKeys.keys[i].armor();
	} else {
		return this.keyring.publicKeys.keys[i].armor();
	}
}

rc_openpgpjs_crypto.prototype.getKeyUserids = function (i, getPrivate) {
	if(typeof(getPrivate) == "undefined") {
		getPrivate = false;
	}

	if(getPrivate) {
		return this.keyring.privateKeys.keys[i].userIds;
	} else {
		return this.keyring.publicKeys.keys[i].userIds;
	}
}

module.exports = rc_openpgpjs_crypto;
