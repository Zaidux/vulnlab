#!/usr/bin/env node
const { Connection, PublicKey, Keypair, LAMPORTS_PER_SOL, Transaction, SystemProgram, sendAndConfirmTransaction } = require('@solana/web3.js');
const bs58 = require('bs58').default;
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { getOrCreateAssociatedTokenAccount, transfer } = require('@solana/spl-token');

const args = process.argv.slice(2);
const command = args[0] || 'help';
const configDir = path.join(process.env.HOME, '.config', 'solana', 'cli');
const configFile = path.join(configDir, 'config.yml');

function loadConfig() {
    try {
        const yaml = fs.readFileSync(configFile, 'utf8');
        const jsonUrl = yaml.match(/json_rpc_url:\s*["']?([^"'\s]+)/)?.[1] || 'https://api.mainnet-beta.solana.com';
        const keypairPath = yaml.match(/keypair_path:\s*["']?([^"'\s]+)/)?.[1] || path.join(configDir, 'id.json');
        const commitment = yaml.match(/commitment:\s*["']?([^"'\s]+)/)?.[1] || 'confirmed';
        return { jsonUrl, keypairPath, commitment };
    } catch {
        return { jsonUrl: 'https://api.mainnet-beta.solana.com', keypairPath: path.join(configDir, 'id.json'), commitment: 'confirmed' };
    }
}

function saveConfig(jsonUrl, keypairPath, commitment) {
    fs.mkdirSync(configDir, { recursive: true });
    const yaml = `json_rpc_url: ${jsonUrl}\nkeypair_path: ${keypairPath}\ncommitment: ${commitment}\n`;
    fs.writeFileSync(configFile, yaml);
}

async function main() {
    const config = loadConfig();
    const connection = new Connection(config.jsonUrl, config.commitment);

    switch(command) {
        case '--version':
        case '-V':
            console.log('solana-cli 1.18.26 (via @solana/web3.js)');
            break;
            
        case 'config':
            if (args[1] === 'get') {
                console.log('Config File:', configFile);
                console.log('RPC URL:', config.jsonUrl);
                console.log('WebSocket URL:', config.jsonUrl.replace('https', 'wss'));
                console.log('Keypair Path:', config.keypairPath);
                console.log('Commitment:', config.commitment);
            } else if (args[1] === 'set') {
                let newUrl = config.jsonUrl;
                let updateConfig = false;
                
                for (let i = 2; i < args.length; i++) {
                    if (args[i] === '--url' && args[i+1]) {
                        newUrl = args[i+1];
                        i++;
                        updateConfig = true;
                    } else if (args[i] === '--keypair' && args[i+1]) {
                        config.keypairPath = args[i+1];
                        i++;
                        updateConfig = true;
                    }
                }
                
                saveConfig(newUrl, config.keypairPath, config.commitment);
                console.log('Config Updated:');
                console.log('  RPC URL:', newUrl);
                console.log('  Keypair:', config.keypairPath);
            }
            break;
            
        case 'balance':
            let pubkey;
            if (args[1]) {
                pubkey = new PublicKey(args[1]);
            } else {
                try {
                    const keypairData = JSON.parse(fs.readFileSync(config.keypairPath, 'utf8'));
                    const secretKey = Array.isArray(keypairData) ? Uint8Array.from(keypairData) : Uint8Array.from(keypairData._bnbs || keypairData);
                    pubkey = Keypair.fromSecretKey(secretKey).publicKey;
                } catch (e) {
                    console.error('No keypair found. Run: solana-keygen new');
                    return;
                }
            }
            const balance = await connection.getBalance(pubkey);
            console.log(`${balance / LAMPORTS_PER_SOL} SOL`);
            break;
            
        case 'airdrop':
            if (!args[1]) { console.error('Usage: solana airdrop <PUBKEY> [AMOUNT]'); return; }
            const airdropAmount = parseInt(args[2]) || 1;
            const airdropPubkey = new PublicKey(args[1]);
            try {
                const signature = await connection.requestAirdrop(airdropPubkey, airdropAmount * LAMPORTS_PER_SOL);
                await connection.confirmTransaction(signature);
                console.log(`Airdropped ${airdropAmount} SOL to ${airdropPubkey.toBase58()}`);
                console.log(`Signature: ${signature}`);
            } catch(e) {
                console.error('Airdrop failed:', e.message);
            }
            break;
            
        case 'address':
            try {
                const keypairData = JSON.parse(fs.readFileSync(config.keypairPath, 'utf8'));
                const secretKey = Array.isArray(keypairData) ? Uint8Array.from(keypairData) : Uint8Array.from(keypairData._bnbs || keypairData);
                const keypair = Keypair.fromSecretKey(secretKey);
                console.log(keypair.publicKey.toBase58());
            } catch (e) {
                console.error('No keypair found at:', config.keypairPath);
            }
            break;

        // solana-keygen compatibility
        case 'new':
            if (command === 'new' && args.length > 0) {
                const kp = Keypair.generate();
                const outFile = args[0] || path.join(configDir, 'id.json');
                const secretKey = Array.from(kp.secretKey);
                fs.writeFileSync(outFile, JSON.stringify(secretKey));
                
                // Check for --no-bip39-passphrase (we're using raw keypair, so this is default behavior)
                console.log(`Wrote new keypair to ${outFile}`);
                console.log('===================================================================');
                console.log('pubkey:', kp.publicKey.toBase58());
                console.log('===================================================================');
                console.log('Save this seed phrase to recover your keypair:');
                console.log('(This keypair uses raw keys, no seed phrase available)');
                console.log('===================================================================');
            }
            break;
            
        case 'transfer':
            if (!args[1] || !args[2]) { console.error('Usage: solana transfer <RECIPIENT> <AMOUNT>'); return; }
            const fromKeypair = Keypair.fromSecretKey(
                Uint8Array.from(JSON.parse(fs.readFileSync(config.keypairPath, 'utf8')))
            );
            const toPubkey = new PublicKey(args[1]);
            const amount = parseFloat(args[2]) * LAMPORTS_PER_SOL;
            
            const tx = new Transaction().add(
                SystemProgram.transfer({
                    fromPubkey: fromKeypair.publicKey,
                    toPubkey: toPubkey,
                    lamports: amount,
                })
            );
            
            const txSig = await sendAndConfirmTransaction(connection, tx, [fromKeypair]);
            console.log(`Transferred ${args[2]} SOL to ${args[1]}`);
            console.log(`Signature: ${txSig}`);
            break;
            
        default:
            console.log(`Usage: node solana-cli.js <COMMAND> [ARGS]`);
            console.log('');
            console.log('Commands:');
            console.log('  balance [PUBKEY]            Get SOL balance');
            console.log('  airdrop <PUBKEY> <AMOUNT>   Request SOL airdrop');
            console.log('  address                     Show your public key');
            console.log('  transfer <RECIPIENT> <SOL>  Send SOL');
            console.log('  config get                  Show config');
            console.log('  config set --url <URL>      Set RPC endpoint');
            console.log('  --version, -V               Show version');
            console.log('');
            console.log('Keypair Management:');
            console.log('  Run: node -e "require(\'./solana-cli.js\')" && node solana-cli.js new [OUTFILE]');
    }
}

main().catch(console.error);
