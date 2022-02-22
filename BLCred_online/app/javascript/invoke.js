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

        // data used in test
        var n = '4'
        var m = ["nezuko", "kawaii", "hhh", "lol2333", "ohhhh", "aha", "blcred", "ohyeah", "nezuko", "kawaii", "hhh", "lol2333", "ohhhh", "aha", "blcred", "ohyeah"].slice(0, n)
        var D = '1001010101001011'.substring(0, n)

        // Submit transaction.
        console.time('setup')
        const p = await contract.submitTransaction('setup');
        console.log('setup transaction has been submitted');
        console.timeEnd('setup')
        console.log('go inner timer: ', p.toString().split('|')[0])
        console.log('length of data: ', p.toString().split('|')[1].length);

        console.time('ipkeygen')
        const ask = await contract.submitTransaction('ipkeygen', n);
        console.log('ipkeygen transaction has been submitted');
        console.timeEnd('ipkeygen')
        console.log('go inner timer: ', ask.toString().split('|')[0])
        console.log('length of data: ', ask.toString().split('|')[1].length);
        let fask = path.resolve(__dirname, 'data', 'ask')
        fs.writeFile(fask, ask.toString().split('|')[1], err => {})

        console.time('ukeygen')
        var usk = await contract.submitTransaction('ukeygen');
        console.log('ukeygen transaction has been submitted');
        console.timeEnd('ukeygen')
        console.log('go inner timer: ', usk.toString().split('|')[0])
        console.log('length of data: ', usk.toString().split('|')[1].length);
        usk = usk.toString().split('|')[1]
        let fusk = path.resolve(__dirname, 'data', 'usk')
        fs.writeFile(fusk, usk, err => {})

        console.time('skeygen')
        var ssk = await contract.submitTransaction('skeygen');
        console.log('skeygen transaction has been submitted');
        console.timeEnd('skeygen')
        console.log('go inner timer: ', ssk.toString().split('|')[0])
        console.log('length of data: ', ssk.toString().split('|')[1].length);
        ssk = ssk.toString().split('|')[1]
        let fssk = path.resolve(__dirname, 'data', 'ssk')
        fs.writeFile(fssk, ssk, err => {})

        console.time('issuecred')
        const sigmaCred = await contract.submitTransaction('issuecred', ...m);
        console.log('issuecred transaction has been submitted');
        console.timeEnd('issuecred')
        console.log('go inner timer: ', sigmaCred.toString().split('|')[0])
        console.log('length of data: ', sigmaCred.length - sigmaCred.toString().split('|')[0].length - 1);
        let fsigmaCred = path.resolve(__dirname, 'data', 'sigmaCred')
        fs.writeFile(fsigmaCred, sigmaCred, err => {})

        console.time('deriveshow')
        const sigmaShow = await contract.submitTransaction('deriveshow', usk, D, ...m);
        console.log('deriveshow transaction has been submitted');
        console.timeEnd('deriveshow')
        console.log('go inner timer: ', sigmaShow.toString().split('|')[0])
        // console.log(sigmaShow.toString().split('|')[1])
        console.log('length of data: ', sigmaShow.length - sigmaShow.toString().split('|')[0].length - 1);

        console.time('credverify')
        const result = await contract.submitTransaction('credverify');
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
