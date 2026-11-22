# bedrock-client-api

マイクラ統合版に、パケットベースの外部スクリプト環境を提供するDLLです。

```js
import { host, CommandPermissionLevel } from "bedrock-client-api";
import { ActionFormData } from "bedrock-client-api/ui";

//実行者のxuidをフォームで表示させるコマンドを定義
host.customCommandRegistry.registerCommand({
  name: "getxuid",
  description: "xuidを取得",
  permissionLevel: CommandPermissionLevel.Any,
}, (origin) => {
  const player = origin.sourceEntity;
  new ActionFormData().body(player.xuid).show(player);
});
```

## 留意点

- インジェクターは既存のものを使用してください
- dllは同階層のscriptsを読み込みます
> [!IMPORTANT]
> `/scripts`を読み込ませるため、dllを`grant-access.bat`にドロップしてアクセス権限を付与させてください

## ドキュメント

| ファイル | 内容 |
| --- | --- |
| `bedrock-client-api.d.ts` | 型、概要 |
| `examples/` | サンプル |
