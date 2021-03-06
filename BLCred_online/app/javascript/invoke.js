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
        const p = await contract.submitTransaction('setup');
        console.log('setup transaction has been submitted');
        console.timeEnd('setup')
        console.log('go inner timer: ', p.toString().split('|')[0])
        console.log('length of data: ', p.length);

        console.time('authkeygen')
        const ask = await contract.submitTransaction('authkeygen', '4');
        console.log('authkeygen transaction has been submitted');
        console.timeEnd('authkeygen')
        console.log('go inner timer: ', ask.toString().split('|')[0])
        console.log('length of data: ', ask.length);
        let fask = path.resolve(__dirname, 'data', 'ask')
        fs.writeFile(fask, ask, err => {})

        console.time('ukeygen')
        var usk = await contract.submitTransaction('ukeygen');
        console.log('ukeygen transaction has been submitted');
        console.timeEnd('ukeygen')
        console.log('go inner timer: ', usk.toString().split('|')[0])
        console.log('length of data: ', usk.length);
        usk = usk.toString().split('|')[1]
        let fusk = path.resolve(__dirname, 'data', 'usk')
        fs.writeFile(fusk, usk, err => {})

        var m = ["nezuko", "kawaii", "hhh", "lol2333"]
        console.time('issuecred')
        const sigmaCred = await contract.submitTransaction('issuecred', m[0], m[1], m[2], m[3]);
        console.log('issuecred transaction has been submitted');
        console.timeEnd('issuecred')
        console.log('go inner timer: ', sigmaCred.toString().split('|')[0])
        console.log('length of data: ', sigmaCred.length);
        let fsigmaCred = path.resolve(__dirname, 'data', 'sigmaCred')
        fs.writeFile(fsigmaCred, sigmaCred, err => {})

        var phi = 'BLCredTestPhi'
        var D = '1001'
        console.time('deriveshow')
        const sigmaShow = await contract.submitTransaction('deriveshow', phi, usk, D, m[0], m[1], m[2], m[3]);
        console.log('deriveshow transaction has been submitted');
        console.timeEnd('deriveshow')
        console.log('go inner timer: ', sigmaShow.toString().split('|')[0])
        console.log('length of data: ', sigmaShow.length);

        console.time('credverify')
        const result = await contract.submitTransaction('credverify', phi);
        console.log('credverify transaction has been submitted');
        console.timeEnd('credverify')
        console.log('go inner timer: ', result.toString().split('|')[0])
        if (result.toString().split('|')[1] == '1') {
            console.log('credverify successful');
        }
        else {
            console.log('credverify failure');
        }

        // Disconnect from the gateway.
        await gateway.disconnect();

    } catch (error) {
        console.error(`Failed to submit transaction: ${error}`);
        process.exit(1);
    }
}

main();
