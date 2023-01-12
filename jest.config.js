module.exports = {
    clearMocks: true,
    moduleFileExtensions: ['js', 'json', 'ts'],
    testEnvironment: 'node',
    testMatch: ['**/*.test.ts'],
    testRunner: 'jest-circus/runner',
    transform: {
      '^.+\\.ts$': 'ts-jest'
    },
    verbose: true
};
