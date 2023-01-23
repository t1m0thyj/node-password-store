import { PasswordStore } from "../src";

describe("password-store", () => {
    let passApi: PasswordStore;

    beforeAll(() => {
        passApi = PasswordStore.create("test.pgp", ".password-store");
    }, 60000);

    it("get/setPassword with ASCII string", async () => {
        await passApi.setPassword("TestKeytar", "TestASCII", "ASCII string");
        const password = await passApi.getPassword("TestKeytar", "TestASCII");
        expect(password).toBe("ASCII string");
    });

    it("get/setPassword with mixed character set", async () => {
        await passApi.setPassword("TestKeytar", "TestCharSet", "I 💔 ASCII");
        const password = await passApi.getPassword("TestKeytar", "TestCharSet");
        expect(password).toBe("I 💔 ASCII");
    });

    it("get/setPassword with UTF-16 chars", async () => {
        await passApi.setPassword("TestKeytar", "TestUTF16", "🌞🌙🌟🌴");
        const password = await passApi.getPassword("TestKeytar", "TestUTF16");
        expect(password).toBe("🌞🌙🌟🌴");
    });

    it("get/setPassword with CJK symbols", async () => {
        await passApi.setPassword("TestKeytar", "TestCJK", "「こんにちは世界」");
        const password = await passApi.getPassword("TestKeytar", "TestCJK");
        expect(password).toBe("「こんにちは世界」");
    });

    it("findCredentials prints credentials in test service and verifies member names", async () => {
        const credentials = await passApi.findCredentials("TestKeytar");
        expect(credentials.length).toBe(4);
        expect(credentials[0].account).toBeDefined();
        expect(credentials[0].password).toBeDefined();
        expect(credentials.sort((a, b) => a.account.localeCompare(b.account))).toMatchSnapshot();
    });

    it("findPassword for ASCII string", async () => {
        const password = await passApi.findPassword("TestKeytar/TestASCII");
        expect(password).toBe("ASCII string");
    });

    it("findPassword for mixed character set", async () => {
        const password = await passApi.findPassword("TestKeytar/TestCharSet");
        expect(password).toBe("I 💔 ASCII");
    });

    it("findPassword for UTF-16", async () => {
        const password = await passApi.findPassword("TestKeytar/TestUTF16");
        expect(password).toBe("🌞🌙🌟🌴");
    });

    it("findPassword for CJK symbols", async () => {
        const password = await passApi.findPassword("TestKeytar/TestCJK");
        expect(password).toBe("「こんにちは世界」");
    });

    it("deletePassword deletes all test credentials", async () => {
        let result = await passApi.deletePassword("TestKeytar", "TestASCII");
        expect(result).toBe(true);
        result = await passApi.deletePassword("TestKeytar", "TestCharSet");
        expect(result).toBe(true);
        result = await passApi.deletePassword("TestKeytar", "TestUTF16");
        expect(result).toBe(true);
        result = await passApi.deletePassword("TestKeytar", "TestCJK");
        expect(result).toBe(true);
    });
});
