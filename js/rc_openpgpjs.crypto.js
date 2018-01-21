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

rc_openpgpjs_crypto = {};

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
const encrypt = rc_openpgpjs_crypto.encrypt = function (pubkeys, text, sign, privkey, passphrase) {
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

    if (!privkey[0].decryptSecretMPIs(passphrase)) {
        alert("Password for secrect key was incorrect!");
        return;
	}

    try {
      encrypted = openpgp.write_signed_and_encrypted_message(privkey[0], pubkeys, text);
      return(encrypted);
    } catch (e) {
      return false;
    }
  }

  try {
    encrypted = openpgp.write_encrypted_message(pubkeys, text);
    return(encrypted);
  } catch(e) {
    return false;
  }
}

/**
 * Generates key pair
 *
 * @param bits       {Integer} Key length in bits
 * @param algo       {Integer} Key algorithm type. Currently unused and set to 1 (RSA)
 * @param ident      {String}  Key identity formatted as "Firstname Lastname <foo@bar.com>"
 * @param passphrase {String} Passphrase of private key
 * @return {Array} Armored key pair
 */
const generateKeys = rc_openpgpjs_crypto.generateKeys = function (bits, algo, ident, passphrase) {
  try {
    keys = openpgp.generate_key_pair(1, bits, ident, passphrase);
    arr = new Array();
    arr["private"] = keys.privateKeyArmored;
    arr["public"] = keys.publicKeyArmored;
    return(arr);
  } catch(e) {
    return false;
  }
}

/**
 * Sign a meesage
 *
 * @param msg             {String} Message to sign
 * @param privkey_armored {String} Armored private key to sign message
 * @param passphrase      {String} Passphrase of private key
 * @return {String} Signed message
 */
const sign = rc_openpgpjs_crypto.sign = function (msg, privkey_armored, passphrase) {
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
const decrypt = rc_openpgpjs_crypto.decrypt = function (msg, privkey_armored, passphrase) {
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
const verify = rc_openpgpjs_crypto.verify = function (msg, pubkeys) {
  return msg[0].verifySignature(pubkeys);
}


const parseMsg = rc_openpgpjs_crypto.parseMsg = function (msg) {
	return openpgp.read_message(msg);
}

const hasPrivateKey = rc_openpgpjs_crypto.hasPrivateKey = function () {
	return openpgp.keyring.hasPrivateKey();
}

const getPrivkeyCount = rc_openpgpjs_crypto.getPrivkeyCount = function () {
	return openpgp.keyring.privateKeys.length;
}

const getPubkeyCount = rc_openpgpjs_crypto.getPubkeyCount = function () {
	return openpgp.keyring.publicKeys.length;
}

const getFingerprint = rc_openpgpjs_crypto.getFingerprint = function (i, private, niceformat) {
	if(typeof(private) == "undefined") {
		private = false;
	}

	if(typeof(niceformat) == "undefined") {
		niceformat = true;
	}

	if(private == false) {
		fingerprint = util.hexstrdump(openpgp.keyring.publicKeys[i].obj.getFingerprint()).toUpperCase();
	} else {
		fingerprint = util.hexstrdump(openpgp.keyring.privateKeys[i].obj.getFingerprint()).toUpperCase();
	}

	if(niceformat) {
		fingerprint = fingerprint.replace(/(.{2})/g, "$1 ");
	} else {
		fingerprint = "0x" + fingerprint.substring(0, 8);
	}

	return fingerprint;
}

const getKeyID = rc_openpgpjs_crypto.getKeyID = function (i, private) {
	if(typeof(private) == "undefined") {
		private = false;
	}

	if(private == false) {
		key_id = "0x" + util.hexstrdump(openpgp.keyring.publicKeys[i].obj.getKeyId()).toUpperCase().substring(8);
	} else {
		key_id = "0x" + util.hexstrdump(openpgp.keyring.privateKeys[i].obj.getKeyId()).toUpperCase().substring(8);
	}

	return key_id;
}

const getPerson = rc_openpgpjs_crypto.getPerson = function (i, j, private) {
	if(typeof(private) == "undefined") {
		private = false;
	}

	if(private == false) {
		person = openpgp.keyring.publicKeys[i].obj.userIds[j].text;
	} else {
		person = openpgp.keyring.privateKeys[i].obj.userIds[j].text;
	}

	return person;
}

const getPubkeyForAddress = rc_openpgpjs_crypto.getPubkeyForAddress = function (address) {
	var pubkey = openpgp.keyring.getPublicKeyForAddress(address);
	return pubkey;
}

const getFingerprintForSender = rc_openpgpjs_crypto.getFingerprintForSender = function (sender) {
	var pubkey = getPubkeyForAddress(sender);
	var fingerprint = util.hexstrdump(pubkey[0].obj.getFingerprint()).toUpperCase().substring(8).replace(/(.{2})/g,"$1 ");
	return fingerprint;
}

const getPrivkeyArmored = rc_openpgpjs_crypto.getPrivkeyArmored = function (id) {
	var keyid = openpgp.keyring.privateKeys[id].obj.getKeyId();
	var privkey_armored = openpgp.keyring.getPrivateKeyForKeyId(keyid)[0].key.armored;
	return privkey_armored;
}

const getPrivkeyObj = rc_openpgpjs_crypto.getPrivkeyObj = function (id) {
	var privkey_armored = getPrivkeyArmored(id);
    return privkey = openpgp.read_privateKey(privkey_armored);
}

// Gets privkey obj from armored
const getPrivkey = rc_openpgpjs_crypto.getPrivkey = function (armored) {
	var privkey = openpgp.read_privateKey(armored);
	return privkey;
}

const decryptSecretMPIs = rc_openpgpjs_crypto.decryptSecretMPIs = function (i, p) {
	return openpgp.keyring.privateKeys[i].obj.decryptSecretMPIs(p);
}

const decryptSecretMPIsForId = rc_openpgpjs_crypto.decryptSecretMPIsForId = function (id, passphrase) {
	var keyid = openpgp.keyring.privateKeys[id].obj.getKeyId();
	var privkey_armored = openpgp.keyring.getPrivateKeyForKeyId(keyid)[0].key.armored;
	var privkey = getPrivkey(privkey_armored);
	return privkey[0].decryptSecretMPIs(passphrase);
}

const importPubkey = rc_openpgpjs_crypto.importPubkey = function (key) {
	try {
		openpgp.keyring.importPublicKey(key);
		openpgp.keyring.store();
	} catch(e) {
		console.log(e);
		return false;
	}
	return true;
}

const importPrivkey = rc_openpgpjs_crypto.importPrivkey = function (key, passphrase) {
	try {
		openpgp.keyring.importPrivateKey(key, passphrase);
		openpgp.keyring.store();
	} catch(e) {
		return false;
	}

	return true;
}

const parsePrivkey = rc_openpgpjs_crypto.parsePrivkey = function (key) {
	try {
		return openpgp.read_privateKey(key)[0];
	} catch(e) {
		return false;
	}
}

const removeKey = rc_openpgpjs_crypto.removeKey = function (i, private) {
	if(typeof(private) == "undefined") {
		private = false;
	}

	if(private) {
		return openpgp.keyring.removePrivateKey(i);
	}

	return openpgp.keyring.removePublicKey(i);
}

const verifyBasicSignatures = rc_openpgpjs_crypto.verifyBasicSignatures = function (i) {
	return (openpgp.keyring.publicKeys[i].obj.verifyBasicSignatures() ? true : false);
}

/**
 * Extract the algorithm string from a key and return the algorithm type.
 *
 * @param i {Integer} Key id in keyring
 * @return {String} Algorithm type
 */

const getAlgorithmString = rc_openpgpjs_crypto.getAlgorithmString = function (i, private) {
	if(typeof(private) == "undefined") {
		private = false;
	}

	if(private) {
		key = openpgp.keyring.privateKeys[i].obj;
	} else {
		key = openpgp.keyring.publicKeys[i].obj;
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

const exportArmored = rc_openpgpjs_crypto.exportArmored = function (i, private) {
	if(typeof(private) == "undefined") {
		private = false;
	}

	if(private) {
		return openpgp.keyring.privateKeys[i].armored;
	} else {
		return openpgp.keyring.publicKeys[i].armored;
	}
}

const getKeyUserids = rc_openpgpjs_crypto.getKeyUserids = function (i, private) {
	if(typeof(private) == "undefined") {
		private = false;
	}

	if(private) {
		return openpgp.keyring.privateKeys[i].obj.userIds;
	} else {
		return openpgp.keyring.publicKeys[i].obj.userIds;
	}
}

module.exports = rc_openpgpjs_crypto;
