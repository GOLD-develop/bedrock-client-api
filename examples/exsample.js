import { host, client, system, CommandPermissionLevel, CustomCommandParamType, BossBar } from "bedrock-client-api";
import { ActionFormData, ModalFormData } from "bedrock-client-api/ui";
import { fetch } from "http";

//きもいサンプル

client.customCommandRegistry.registerCommand({
  name: "spam",
  description: "悪質なスパム(BAN注意)",
  permissionLevel: CommandPermissionLevel.Any,
  mandatoryParameters: [
    {
      name: "chatmsg",
      type: CustomCommandParamType.Message
    }
  ]
}, (origin, chatmsg) => {
  const player = origin.sourceEntity;
  if (chatmsg === "" || chatmsg === undefined) return;
  for (let i = 0; i < 10; i++) {
    player.chat(chatmsg);
  }
});

client.customCommandRegistry.registerCommand({
  name: "getplayerdata",
  description: "プレイヤーの詳細データを取得",
  permissionLevel: CommandPermissionLevel.Any
}, async (origin) => {
  const player = origin.sourceEntity;
  const players = host.getPlayers();
  const form = new ActionFormData().body(`${players.length}人のプレイヤー`);
  players.forEach(p => form.button(p.name));
  const res = await form.show(player);
  if (res.canceled) return;
  const selected = players[res.selection];
  await system.waitTicks(1);
  new ActionFormData().body(`${selected.name}の詳細:\n  -connection: ${selected.connection}\n  -uuid: ${selected.uuid}\n  -xuid: ${selected.xuid}\n  -os: ${selected.device.os}\n  -model: ${selected.device.model}\n  -deviceId: ${selected.device.id}\n  -version: ${selected.gameVersion}\n  -language: ${selected.language}\n  -input: ${selected.inputMode}`).show(player);
});

client.customCommandRegistry.registerCommand({
  name: "timer",
  description: "ボスバーを使ったタイマー",
  permissionLevel: CommandPermissionLevel.Any,
  mandatoryParameters: [
    {
      name: "seconds",
      type: CustomCommandParamType.Integer
    }
  ]
}, (origin, sec) => {
  const totalTicks = sec * 20;
  const bar = new BossBar({
    title: "タイマー(準備中)",
    color: "yellow",
    percent: 1
  });
  bar.show(client);
  let elapsedTicks = 0;
  let lastShownSeconds = sec;
  bar.title = `タイマー(残り${sec}秒)`;
  const id = system.runInterval(() => {
    elapsedTicks++;
    const remainingTicks = totalTicks - elapsedTicks;
    bar.percent = Math.max(0, remainingTicks / totalTicks);
    if (remainingTicks <= 0) {
      system.clearRun(id);
      bar.remove();
      return;
    }
    const remainingSeconds = Math.ceil(remainingTicks / 20);
    if (remainingSeconds !== lastShownSeconds) {
      lastShownSeconds = remainingSeconds;
      bar.title = `タイマー(残り${remainingSeconds}秒)`;
    }
  }, 1);
});

system.beforeEvents.startup.subscribe(({ customCommandRegistry }) => {
  customCommandRegistry.registerCommand({
    name: "webdata",
    description: "webにアクセス",
    permissionLevel: CommandPermissionLevel.Any
  }, async (origin) => {
    const player = origin.sourceEntity;
    const res = await new ModalFormData().textField("url").show(player);
    if (res.canceled) return;
    const webData = await fetch(res.formValues[0]);
    if (!webData.ok) return;
    const textData = await webData.text();
    new ActionFormData().body(textData).show(player);
  });

  customCommandRegistry.registerCommand({
    name: "test",
    description: "hud関連をテスト",
    permissionLevel: CommandPermissionLevel.Any
  }, origin => {
    const player = origin.sourceEntity;
    player.sendMessage("メッセージ");
    player.setActionBar("アクションバー");
    player.showTitle("タイトル", "サブタイトル");
    player.toast("招待のやつ");
  });
  customCommandRegistry.hideCommand("me");
  customCommandRegistry.hideCommand("msg");
  customCommandRegistry.hideCommand("w");
});

host.beforeEvents.commandSend.subscribe(event => {
  const { command, sender: player } = event;
  const [name, ...args] = command.replace(/^\//, "").split(/\s+/);
  const banned = ["tell"];
  if (!banned.includes(name)) return;
  event.cancel = true;
  player.toast("§c/tell?使おうとしたこと全部バレてんだよ");
});

host.afterEvents.playerLogin.subscribe(({ player }) => {
  console.log(`${player.name}がゲームに参加しました(使用機種: ${player.device.os})`);
});