import * as fs from "fs";
import * as os from "os";
import * as path from "path";

export class PasswordStore {
    private kbpgp: any;
    private keyManager: any;
    private passwordStoreDir: string;

    private constructor(private privateKeyFile: string, passwordStoreDir?: string) {
        this.kbpgp = require("kbpgp");
        this.passwordStoreDir = passwordStoreDir ?? path.join(os.homedir(), ".password-store");
    }

    public static async create(privateKeyFile: string, passwordStoreDir?: string): Promise<PasswordStore> {
        const instance = new PasswordStore(privateKeyFile, passwordStoreDir);
        if (fs.existsSync(instance.privateKeyFile)) {
            return new Promise((resolve, reject) => {
                instance.kbpgp.KeyManager.import_from_armored_pgp({
                    armored: fs.readFileSync(instance.privateKeyFile, "utf-8")
                }, (err: Error | null, key: any) => {
                    if (err) return reject(err);
                    instance.keyManager = key;
                    resolve(instance);
                });
            });
        } else {
            // TODO Prompt for private key passphrase?
            return new Promise((resolve, reject) => {
                instance.kbpgp.KeyManager.generate_rsa({
                    userid: os.userInfo().username
                }, (err: Error | null, key: any) => {
                    if (err) return reject(err);
                    instance.keyManager = key;
                    key.sign({}, (err: Error | null) => {
                        if (err) return reject(err);
                        key.export_pgp_private({}, (err: Error | null, pgpPrivate: string) => {
                            if (err) return reject(err);
                            fs.writeFileSync(instance.privateKeyFile, pgpPrivate, { mode: 0o600 });
                            key.export_pgp_public({}, (err: Error | null, pgpPublic: string) => {
                                if (err) return reject(err);
                                fs.writeFileSync(instance.privateKeyFile + ".pub", pgpPublic, { mode: 0o644 });
                                resolve(instance);
                            });
                        });
                    });
                });
            });
        }
    }

    public getPassword(service: string, account: string): Promise<string | null> {
        const passwordFile = path.join(this.passwordStoreDir, service, account) + ".gpg";
        if (fs.existsSync(passwordFile)) {
            const ring = new this.kbpgp.keyring.KeyRing();
            ring.add_key_manager(this.keyManager);
            return new Promise((resolve, reject) => {
                this.kbpgp.unbox(
                    { keyfetch: ring, raw: fs.readFileSync(passwordFile) },
                    (err: Error | null, literals: any) => {
                        if (err) return reject(err);
                        resolve(literals[0].toString().slice(0, -1));
                    }
                );
            });
        } else {
            return Promise.resolve(null);
        }
    }

    public setPassword(service: string, account: string, password: string): Promise<void> {
        const passwordFile = path.join(this.passwordStoreDir, service, account) + ".gpg";
        fs.mkdirSync(path.dirname(passwordFile), { mode: 0o700, recursive: true });
        return new Promise((resolve, reject) => {
            this.kbpgp.box({
                msg: Buffer.from(password + "\n"),
                encrypt_for: this.keyManager
            }, (err: Error | null, _: string, result: Buffer) => {
                if (err) return reject(err);
                resolve(fs.writeFileSync(passwordFile, result, { mode: 0o600 }));
            });
        });
    }

    public deletePassword(service: string, account: string): Promise<boolean> {
        // TODO Verify key before deletion?
        const passwordFile = path.join(this.passwordStoreDir, service, account) + ".gpg";
        if (fs.existsSync(passwordFile)) {
            return new Promise((resolve, reject) => {
                fs.rm(passwordFile, (err: Error | null) => {
                    if (err) return reject(err);
                    resolve(true);
                })
            });
        } else {
            return Promise.resolve(false);
        }
    }

    public findCredentials(service: string): Promise<{ account: string; password: string }[]> {
        const serviceDir = path.join(this.passwordStoreDir, service);
        const credentials: { account: string; password: string }[] = [];
        return new Promise((resolve, reject) => {
            fs.readdir(serviceDir, (err: Error | null, files: string[]) => {
                if (err) return reject(err);
                Promise.all(files.filter((file) => file.endsWith(".gpg"))
                    .map((file) => {
                        const account = file.slice(0, -4);
                        return this.getPassword(service, account)
                            .then((password) => {
                                if (password) credentials.push({ account, password });
                            });
                    })
                ).then(() => resolve(credentials));
            });
        });
    }

    public findPassword(service: string): Promise<string | null> {
        return this.getPassword("", service);
    }
}
