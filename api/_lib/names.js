// 不適切・紛らわしいユーザー名の判定(登録時だけ。ログインには使わない)。
// 完全には防げない。誤って弾く例(Scunthorpe問題)を減らすため、短い英語は「単語として一致」したときだけ弾く。
// 見逃しや誤検出は、運営が管理画面で対応する。環境変数 BLOCKED_NAME_TERMS(カンマ区切り)で、コードを変えずに語を足せる。
const { normUsername } = require('./auth');

// 運営やサイトになりすます名前(単語として一致したら不可。末尾の数字・記号は無視)
const IMPERSONATE = new Set(['admin', 'administrator', 'root', 'system', 'sysadmin', 'moderator', 'mod', 'staff',
  'support', 'official', 'owner', 'operator', 'dakendojo', 'daken', '打鍵道場']);
// 日本語で運営を名乗る語(含まれていたら不可)
const IMPERSONATE_JA = ['運営', '管理者', '管理人', '公式', 'うんえい', 'かんりにん'];

// 英語: これを「含む」名前は不可(誤って弾きにくい、長くて特徴的な語だけ)
const PROFANE_CONTAINS = ['fuck', 'nigger', 'nigga', 'faggot', 'bitch', 'whore', 'rapist', 'hitler', 'porn', 'pussy',
  'blowjob', 'handjob', 'cumshot', 'dildo', 'jizz', 'asshole', 'dickhead', 'chinpo', 'chinko', 'manko', 'sekkusu'];
// 英語: 「単語として一致」したときだけ不可(短い語。class や pass を弾かないため)
const PROFANE_WORDS = new Set(['sex', 'sexy', 'ass', 'asses', 'dick', 'cock', 'tits', 'boobs', 'slut', 'rape', 'rapes',
  'nazi', 'anal', 'cum', 'fag', 'fags', 'shit', 'shitty', 'bullshit', 'cunt', 'porno', 'orgy']);
// 日本語: ひらがなにそろえて「含む」もの(カタカナ・全角半角は事前にそろえる)
const PROFANE_JA_CONTAINS = ['ちんぽ', 'ちんこ', 'まんこ', 'せっくす', 'れいぷ', 'きちがい', 'びっち', 'やりまん', 'おなにー',
  '死ね', '氏ね', '殺すぞ', '殺してやる', '殺せ', '池沼', '基地外', '強姦', '輪姦', '中出し', '乱交', '援交'];
// 日本語: 上の語を含んでしまう、ごく普通の言葉(先に取り除いてから判定する)
const OK_JA_WORDS = ['まんこく', 'まんこう', 'ちんこう', 'ちんこん'];
// 日本語: 名前全体がこれと同じときだけ不可(ほかの単語に含まれやすい語)
const PROFANE_JA_EXACT = new Set(['しね', 'がいじ', 'ころす', 'ばか', 'あほ']);

const LEET = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's', '!': 'i', '+': 't' };
const toHiragana = s => s.replace(/[ァ-ヶ]/g, c => String.fromCharCode(c.charCodeAt(0) - 0x60));
const squash = s => s.replace(/[^\p{L}\p{N}]+/gu, '');
const words = s => s.split(/[^\p{L}\p{N}]+/u).filter(Boolean);
const stripTail = w => w.replace(/[0-9]+$/, '');
const deLeet = s => Array.from(s).map(c => LEET[c] || c).join('');

function extraTerms() {
  return String(process.env.BLOCKED_NAME_TERMS || '').split(',').map(t => squash(toHiragana(normUsername(t)))).filter(Boolean);
}

// 引数は normUsername() を通した名前。戻り値: null(問題なし) か 'impersonation' / 'profanity'
function nameProblem(name) {
  const folded = toHiragana(name);
  const sq = squash(folded);
  const sqLeet = squash(deLeet(folded));
  const ws = words(folded).map(stripTail);
  const wsLeet = words(deLeet(folded)).map(stripTail);

  if (ws.some(w => IMPERSONATE.has(w)) || IMPERSONATE.has(sq.replace(/[0-9]+$/, ''))) return 'impersonation';
  if (IMPERSONATE_JA.some(t => sq.includes(toHiragana(t)))) return 'impersonation';

  if (PROFANE_CONTAINS.some(t => sqLeet.includes(t))) return 'profanity';
  if (wsLeet.some(w => PROFANE_WORDS.has(w)) || ws.some(w => PROFANE_WORDS.has(w))) return 'profanity';
  const sqOk = OK_JA_WORDS.reduce((acc, w) => acc.split(toHiragana(w)).join(''), sq);
  if (PROFANE_JA_CONTAINS.some(t => sqOk.includes(toHiragana(t)))) return 'profanity';
  if (PROFANE_JA_EXACT.has(sq)) return 'profanity';
  if (extraTerms().some(t => sq.includes(t) || sqLeet.includes(t))) return 'profanity';
  return null;
}

module.exports = { nameProblem };
