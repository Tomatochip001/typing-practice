// ユーザーが書いた自由記述(備考など)の整理。制御文字(NULを含む)を除き、長さを決める。
function cleanText(s, max) {
  if (typeof s !== 'string') return '';
  const t = s.normalize('NFC').replace(/\r\n?/g, '\n').replace(/[\p{Cc}\p{Cs}\p{Co}]/gu, c => c === '\n' ? '\n' : ' ').trim();
  return Array.from(t).slice(0, max).join('');
}
module.exports = { cleanText };
