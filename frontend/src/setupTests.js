// jsdom (jest 27) predates the Web globals that newer dependencies expect;
// polyfill them before any test module imports execute.
import { TextDecoder, TextEncoder } from 'util';

global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;
