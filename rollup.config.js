import commonjs from "@rollup/plugin-commonjs";
import resolve from "@rollup/plugin-node-resolve";
import babel from "@rollup/plugin-babel";
import typescript from "rollup-plugin-typescript2";
import pkg from "./package.json";

import { terser } from "rollup-plugin-terser";
import { builtinModules as builtin } from "module";

const extensions = [".js", ".ts"];

export default {
  input: "./src/index.ts",

  plugins: [
    // Allows node_modules resolution
    resolve({ extensions }),

    // Allow bundling cjs modules. Rollup doesn't understand cjs
    commonjs(),

    typescript({
      useTsconfigDeclarationDir: true,
      exclude: ["__tests__"],
    }),

    // Compile TypeScript/JavaScript files
    babel({
      extensions,
      babelHelpers: "bundled",
      include: ["./src/**/*"],
    }),

    terser({
      module: true,
      compress: true,
    }),
  ],

  output: [
    {
      file: pkg.main,
      format: "cjs",
    },
    {
      file: pkg.module,
      format: "esm",
    },
  ],

  // Specify here external modules which you don't want to include in your bundle (for instance: 'lodash', 'moment' etc.)
  // https://rollupjs.org/guide/en/#external
  external: Object.keys(pkg.devDependencies)
    .concat(builtin)
    .filter((node_mod) => node_mod !== "fast-jwt"),
};
