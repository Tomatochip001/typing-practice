// 環境変数から上限値などを読む。未設定・不正な値のときは既定値を使う。
const num = (name, def) => {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? v : def;
};

module.exports = {
  // 新規登録の緊急停止スイッチ: REGISTRATION_OPEN=0 で停止
  registrationOpen: () => process.env.REGISTRATION_OPEN !== '0',
  maxUsers: () => num('MAX_USERS', 300),
  maxRegistrationsPerDay: () => num('MAX_REGISTRATIONS_PER_DAY', 30),
  registerPerIpPerHour: () => num('REGISTER_PER_IP_PER_HOUR', 3),
  syncPerUserPer10Min: () => num('SYNC_PER_USER_PER_10MIN', 60)
};
