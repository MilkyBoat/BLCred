/*
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';

const { FileSystemWallet, Gateway } = require('fabric-network');
const fs = require('fs')
const path = require('path');

const ccpPath = path.resolve(__dirname, '..', '..', 'scripts', 'connection-org1.json');

async function main() {
    try {

        // Create a new file system based wallet for managing identities.
        const walletPath = path.join(process.cwd(), 'wallet');
        const wallet = new FileSystemWallet(walletPath);
        console.log(`Wallet path: ${walletPath}`);

        // Check to see if we've already enrolled the user.
        const userExists = await wallet.exists('user1');
        if (!userExists) {
            console.log('An identity for the user "user1" does not exist in the wallet');
            console.log('Run the registerUser.js application before retrying');
            return;
        }

        // Create a new gateway for connecting to our peer node.
        const gateway = new Gateway();
        await gateway.connect(ccpPath, { wallet, identity: 'user1', discovery: { enabled: true, asLocalhost: true } });

        // Get the network (channel) our contract is deployed to.
        const network = await gateway.getNetwork('mychannel');

        // Get the contract from the network.
        const contract = network.getContract('blcred');

        // Submit transaction.
        console.time('setup')
        await contract.submitTransaction('setup');
        console.log('setup transaction has been submitted');
        console.timeEnd('setup')

        console.time('authkeygen')
        const ak = await contract.submitTransaction('authkeygen', '4');
        console.log('authkeygen transaction has been submitted');
        console.timeEnd('authkeygen')
        console.log('length of data: ', ak.length);
        var ask = ak.slice(0, 40).toString()
        let fask = path.resolve(__dirname, 'data', 'ask')
        fs.writeFile(fask, ask, err => {})
        var avk = ak.slice(40, ak.length).toString()
        let favk = path.resolve(__dirname, 'data', 'avk')
        fs.writeFile(favk, avk, err => {})

        console.time('ukeygen')
        const uk = await contract.submitTransaction('ukeygen');
        console.log('ukeygen transaction has been submitted');
        console.timeEnd('ukeygen')
        console.log('length of data: ', uk.length);
        var usk = uk.slice(0, 8).toString()
        let fusk = path.resolve(__dirname, 'data', 'usk')
        fs.writeFile(fusk, usk, err => {})
        var uvk = uk.slice(8, uk.length).toString()
        let fuvk = path.resolve(__dirname, 'data', 'uvk')
        fs.writeFile(fuvk, uvk, err => {})

        console.time('issuecred')
        var m = ['1234', 'abcd', 'nezuko', 'kawaii']
        const sigmaCred = await contract.submitTransaction('issuecred', uvk, avk, m[0], m[1], m[2], m[3]);
        console.log('issuecred transaction has been submitted');
        console.timeEnd('issuecred')
        console.log('length of data: ', sigmaCred.length);
        let fsigmaCred = path.resolve(__dirname, 'data', 'sigmaCred')
        fs.writeFile(fsigmaCred, sigmaCred, err => {})

        console.time('deriveshow')

        console.timeEnd('deriveshow')

        console.time('credverify')

        console.timeEnd('credverify')

        // Disconnect from the gateway.
        await gateway.disconnect();

    } catch (error) {
        console.error(`Failed to submit transaction: ${error}`);
        process.exit(1);
    }
}

main();
