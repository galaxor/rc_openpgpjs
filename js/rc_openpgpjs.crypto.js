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
 * @param privkey {String} Required if sign is True
 * @return {String} Encrypted message
 */
// TODO: Feed key armored and do openpgp.read_* here
rc_openpgpjs_crypto.prototype.encrypt = function (pubkeys, text, sign, privkey, passphrase) {
  sign = (typeof sign === "undefined") ? 0 : 1;
  if(sign) {
    privkey = (typeof privkey === "undefined") ? 0 : privkey;
    passphrase = (typeof passphrase === "undefined") ? 0 : passphrase;

    if(!privkey) {
      alert("missing privkey");
      return false;
    }

    if(!passphrase) {
      alert("missing passphrase");
      return false;
    }

    if (!privkey.decrypt(passphrase)) {
        alert("Password for secrect key was incorrect!");
        return;
    }

    try {
      const encrypted = openpgp.encrypt(text, pubkeys, privkey, passphrase, undefined, true);
      return(encrypted);
    } catch (e) {
      return false;
    }
  }

  try {
    const encrypted = openpgp.encrypt(text, pubkeys, undefined, undefined, undefined, true);
    return(encrypted);
  } catch(e) {
    return false;
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
 * Sign a meesage
 *
 * @param msg             {String} Message to sign
 * @param privkey_armored {String} Armored private key to sign message
 * @param passphrase      {String} Passphrase of private key
 * @return {String} Signed message
 */
rc_openpgpjs_crypto.prototype.sign = function (msg, privkey_armored, passphrase) {
  var priv_key = openpgp.read_privateKey(privkey_armored);

  if(!priv_key[0].decryptSecretMPIs(passphrase)) {
	alert("WRONG PASS");
  }

  try {
    var signed = openpgp.write_signed_message(priv_key[0], msg);
	return(signed);
  } catch(e) {
    return false;
  }
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
	return this.keyring.privateKeys.length > 0;
}

rc_openpgpjs_crypto.prototype.getPrivkeyCount = function () {
	return this.keyring.privateKeys.length;
}

rc_openpgpjs_crypto.prototype.getPubkeyCount = function () {
	return this.keyring.publicKeys.length;
}

rc_openpgpjs_crypto.prototype.getFingerprint = function (i, private, niceformat) {
	if(typeof(private) == "undefined") {
		private = false;
	}

	if(typeof(niceformat) == "undefined") {
		niceformat = true;
	}

	if(private == false) {
		fingerprint = util.hexstrdump(this.keyring.publicKeys[i].getFingerprint()).toUpperCase();
	} else {
		fingerprint = util.hexstrdump(this.keyring.privateKeys[i].getFingerprint()).toUpperCase();
	}

	if(niceformat) {
		fingerprint = fingerprint.replace(/(.{2})/g, "$1 ");
	} else {
		fingerprint = "0x" + fingerprint.substring(0, 8);
	}

	return fingerprint;
}

rc_openpgpjs_crypto.prototype.getKeyID = function (i, private) {
	if(typeof(private) == "undefined") {
		private = false;
	}

	if(private == false) {
		key_id = "0x" + util.hexstrdump(this.keyring.publicKeys[i].getKeyId()).toUpperCase().substring(8);
	} else {
		key_id = "0x" + util.hexstrdump(this.keyring.privateKeys[i].getKeyId()).toUpperCase().substring(8);
	}

	return key_id;
}

rc_openpgpjs_crypto.prototype.getPerson = function (i, j, private) {
	if(typeof(private) == "undefined") {
		private = false;
	}

	if(private == false) {
		person = this.keyring.publicKeys[i].userIds[j].text;
	} else {
		person = this.keyring.privateKeys[i].userIds[j].text;
	}

	return person;
}

rc_openpgpjs_crypto.prototype.getPubkeyForAddress = function (address) {
	var pubkey = this.keyring.publicKeys.getForId(address);
	return pubkey;
}

rc_openpgpjs_crypto.prototype.getFingerprintForSender = function (sender) {
	var pubkey = this.getPubkeyForAddress(sender);
	var fingerprint = util.hexstrdump(pubkey[0].getFingerprint()).toUpperCase().substring(8).replace(/(.{2})/g,"$1 ");
	return fingerprint;
}

rc_openpgpjs_crypto.prototype.getPrivkeyArmored = function (id) {
	var keyid = this.keyring.privateKeys[id].getKeyId();
	var privkey_armored = this.keyring.privateKeys.getForId(keyid)[0].key.armored;
	return privkey_armored;
}

rc_openpgpjs_crypto.prototype.getPrivkeyObj = function (id) {
	var privkey_armored = getPrivkeyArmored(id);
    return privkey = openpgp.read_privateKey(privkey_armored);
}

// Gets privkey obj from armored
rc_openpgpjs_crypto.prototype.getPrivkey = function (armored) {
	var privkey = openpgp.read_privateKey(armored);
	return privkey;
}

rc_openpgpjs_crypto.prototype.decryptSecretMPIs = function (i, p) {
	return this.keyring.privateKeys[i].decryptSecretMPIs(p);
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
		console.log(e);
		return false;
	}
	return true;
}

rc_openpgpjs_crypto.prototype.importPrivkey = function (key, passphrase) {
	try {
		this.keyring.importPrivateKey(key, passphrase);
		this.keyring.store();
	} catch(e) {
		return false;
	}

	return true;
}

rc_openpgpjs_crypto.prototype.parsePrivkey = function (key) {
	try {
		return openpgp.read_privateKey(key)[0];
	} catch(e) {
		return false;
	}
}

rc_openpgpjs_crypto.prototype.removeKey = function (i, private) {
	if(typeof(private) == "undefined") {
		private = false;
	}

	if(private) {
		return this.keyring.removePrivateKey(i);
	}

	return this.keyring.removePublicKey(i);
}

rc_openpgpjs_crypto.prototype.verifyBasicSignatures = function (i) {
	return (this.keyring.publicKeys[i].verifyBasicSignatures() ? true : false);
}

/**
 * Extract the algorithm string from a key and return the algorithm type.
 *
 * @param i {Integer} Key id in keyring
 * @return {String} Algorithm type
 */

rc_openpgpjs_crypto.prototype.getAlgorithmString = function (i, private) {
	if(typeof(private) == "undefined") {
		private = false;
	}

	if(private) {
		key = this.keyring.privateKeys[i].obj;
	} else {
		key = this.keyring.publicKeys[i].obj;
	}

	if(typeof(key.publicKeyPacket) !== "undefined") {
		var result = key.publicKeyPacket.MPIs[0].mpiByteLength * 8 + "/";
		var sw = key.publicKeyPacket.publicKeyAlgorithm;
	} else {
		// For some reason publicKeyAlgorithm doesn't work directly on the privatekeyPacket, heh
		var result = (key.privateKeyPacket.publicKey.MPIs[0].mpiByteLength * 8 + "/");
		var sw = key.privateKeyPacket.publicKey.publicKeyAlgorithm;
	}

	result += typeToStr(sw);
	return result;
}

rc_openpgpjs_crypto.prototype.exportArmored = function (i, private) {
	if(typeof(private) == "undefined") {
		private = false;
	}

	if(private) {
		return this.keyring.privateKeys[i].armored;
	} else {
		return this.keyring.publicKeys[i].armored;
	}
}

rc_openpgpjs_crypto.prototype.getKeyUserids = function (i, private) {
	if(typeof(private) == "undefined") {
		private = false;
	}

	if(private) {
		return this.keyring.privateKeys[i].userIds;
	} else {
		return this.keyring.publicKeys[i].userIds;
	}
}

module.exports = rc_openpgpjs_crypto;
