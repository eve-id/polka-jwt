export default {
  preset: "ts-jest",
  testEnvironment: "node",
  transform: {
    "^.+\\.ts$": "ts-jest",
  },
  testRegex: "(/__tests__/.*|(\\.|/)(test|spec))\\.(js?|ts?)$",
  moduleFileExtensions: ["ts", "js", "json"],
  testPathIgnorePatterns: ["/lib/", "/node_modules/"],
};
