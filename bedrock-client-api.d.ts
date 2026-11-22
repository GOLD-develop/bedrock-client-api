

type Bytes = Uint8Array | ArrayBuffer | number[] | BinaryWriter | PacketBase;
type Direction = "c2s" | "s2c";
type Side = "client" | "server";

declare const console: {
  log(...values: unknown[]): void;
  info(...values: unknown[]): void;
  debug(...values: unknown[]): void;
  warn(...values: unknown[]): void;
  error(...values: unknown[]): void;
};
declare function setTimeout(callback: () => void, milliseconds?: number): number;
declare function setInterval(callback: () => void, milliseconds?: number): number;
declare function clearTimeout(id: number): void;
declare function clearInterval(id: number): void;


interface Signal<Event> {
  subscribe(callback: (event: Event) => void): (event: Event) => void;
  unsubscribe(callback: (event: Event) => void): boolean;
}

interface Cancellable {
  cancel: boolean;
}
type AfterEvent<T> = Readonly<Omit<T, "cancel">>;

type TextType =
  | "chat" | "whisper" | "announcement" | "raw" | "tip" | "system" | "json" | "jsonWhisper" | "jsonAnnouncement"
  | "translation" | "popup" | "jukeboxPopup" | number;


interface PlayerLoginBeforeEvent extends Cancellable {
  readonly player: Player;
  readonly login: LoginPacket;
  readonly protocol: number;
}
interface HostChatSendBeforeEvent extends Cancellable {
  readonly sender: Player;
  message: string;
}
interface HostCommandSendBeforeEvent extends Cancellable {
  readonly sender: Player;
  command: string;
}
interface HostFormResponseBeforeEvent extends Cancellable {
  readonly sender: Player;
  readonly formId: number;
  readonly response: any;
  readonly canceled: boolean;
  readonly cancelReason: number | null;
}

interface HostBeforeEvents {
  readonly playerLogin: Signal<PlayerLoginBeforeEvent>;
  readonly chatSend: Signal<HostChatSendBeforeEvent>;
  readonly commandSend: Signal<HostCommandSendBeforeEvent>;
  readonly formResponse: Signal<HostFormResponseBeforeEvent>;
}
interface HostAfterEvents {
  readonly playerLogin: Signal<AfterEvent<PlayerLoginBeforeEvent>>;
  readonly chatSend: Signal<AfterEvent<HostChatSendBeforeEvent>>;
  readonly commandSend: Signal<AfterEvent<HostCommandSendBeforeEvent>>;
  readonly formResponse: Signal<AfterEvent<HostFormResponseBeforeEvent>>;
}


interface ClientChatSendBeforeEvent extends Cancellable {
  message: string;
}
interface ClientCommandSendBeforeEvent extends Cancellable {
  command: string;
}
interface TextReceiveBeforeEvent extends Cancellable {
  readonly type: TextType;
  readonly sender: string;
  message: string;
  readonly parameters: string[];
}
interface FormShowBeforeEvent extends Cancellable {
  readonly formId: number;
  form: any;
  respond(answer: unknown): void;
  close(): void;
}
interface FormResponseSendBeforeEvent extends Cancellable {
  readonly formId: number;
  readonly response: any;
  readonly canceled: boolean;
}
interface DisconnectBeforeEvent extends Cancellable {
  readonly reason: number;
  message: string | null;
}

interface ClientBeforeEvents {
  readonly chatSend: Signal<ClientChatSendBeforeEvent>;
  readonly commandSend: Signal<ClientCommandSendBeforeEvent>;
  readonly textReceive: Signal<TextReceiveBeforeEvent>;
  readonly formShow: Signal<FormShowBeforeEvent>;
  readonly formResponseSend: Signal<FormResponseSendBeforeEvent>;
  readonly disconnect: Signal<DisconnectBeforeEvent>;
}
interface ClientAfterEvents {
  readonly chatSend: Signal<AfterEvent<ClientChatSendBeforeEvent>>;
  readonly commandSend: Signal<AfterEvent<ClientCommandSendBeforeEvent>>;
  readonly textReceive: Signal<AfterEvent<TextReceiveBeforeEvent>>;
  readonly formShow: Signal<AfterEvent<FormShowBeforeEvent>>;
  readonly formResponseSend: Signal<AfterEvent<FormResponseSendBeforeEvent>>;
  readonly disconnect: Signal<AfterEvent<DisconnectBeforeEvent>>;
}


interface TitleTimes {
  fadeIn?: number;
  stay?: number;
  fadeOut?: number;
}

declare class Player {
  readonly id: number;
  readonly connection: "rakNet" | "address" | "address6" | "netherNet" | "invalid" | number | null;
  readonly isKnown: boolean;
  readonly name: string;
  readonly xuid: string;
  readonly uuid: string;
  readonly protocol: number;
  readonly device: { os: string; model: string; id: string };
  readonly gameVersion: string;
  readonly language: string;
  readonly inputMode: string;
  readonly actorUniqueId: bigint | null;
  readonly actorRuntimeId: bigint | null;
  readonly loginPacket: LoginPacket | undefined;

  sendPacket(packet: PacketBase): void;
  sendMessage(text: string): void;
  setActionBar(text: string): void;
  showTitle(title: string, subtitle?: string, times?: TitleTimes): void;
  toast(title: string, body?: string): void;
  transfer(address: string, port?: number): void;
  kick(message?: string, reason?: number): void;
  showForm(form: ActionFormData | ModalFormData | MessageFormData | object): Promise<FormAnswer>;
}

declare class ClientPlayer extends Player {
  readonly id: -1;
  chat(message: string): void;
  runCommand(command: string, options?: { like?: CommandRequestPacket }): void;
}

interface FormAnswer {
  canceled: boolean;
  cancelReason: number | null;
  response: any;
}

interface Host {
  readonly beforeEvents: HostBeforeEvents;
  readonly afterEvents: HostAfterEvents;
  readonly customCommandRegistry: CustomCommandRegistry;
  readonly players: Player[];
  sendPacket(packet: PacketBase): void;
  getPlayers(): Player[];
  getPlayer(key: number | string): Player | undefined;
  sendMessage(text: string): void;
  showForm(player: Player, form: object): Promise<FormAnswer>;
}
interface Client {
  readonly beforeEvents: ClientBeforeEvents;
  readonly afterEvents: ClientAfterEvents;
  readonly player: ClientPlayer;
  readonly customCommandRegistry: CustomCommandRegistry;
  showForm(player: Player, form: object): Promise<FormAnswer>;
  toast(title: string, body?: string): void;
  sendMessage(text: string): void;
  sendPacket(packet: PacketBase): void;
  chat(message: string): void;
  runCommand(command: string, options?: { like?: CommandRequestPacket }): void;
  showTitle(title: string, subtitle?: string, times?: TitleTimes): void;
  setActionBar(text: string): void;
  setDevice(options: { os?: number | "android" | "ios" | "macos" | "fireos" | "gearvr" | "hololens" | "windows" | "win32" | "dedicated" | "tvos" | "playstation" | "switch" | "xbox" | "windowsPhone" | "linux"; model?: string }): void;
  clearDevice(): void;
}
declare const host: Host;
declare const client: Client;

declare const system: {
  readonly currentTick: number;
  run(callback: () => void): number;
  runTimeout(callback: () => void, ticks?: number): number;
  runInterval(callback: () => void, ticks?: number): number;
  clearRun(id: number): void;
  waitTicks(ticks?: number): Promise<void>;
  readonly beforeEvents: { readonly startup: { subscribe(callback: (event: StartupEvent) => void): (event: StartupEvent) => void } };
};


interface ActionFormResult { canceled: boolean; cancelReason?: number; selection?: number }
interface MessageFormResult { canceled: boolean; cancelReason?: number; selection?: 0 | 1 }
interface ModalFormResult { canceled: boolean; cancelReason?: number; formValues?: unknown[] }

declare class ActionFormData {
  title(text: string): this;
  body(text: string): this;
  button(text: string, iconPath?: string): this;
  show(player: Player): Promise<ActionFormResult>;
}
declare class MessageFormData {
  title(text: string): this;
  body(text: string): this;
  button1(text: string): this;
  button2(text: string): this;
  show(player: Player): Promise<MessageFormResult>;
}
declare class ModalFormData {
  title(text: string): this;
  label(text: string): this;
  textField(label: string, placeholder?: string, defaultValue?: string): this;
  toggle(label: string, defaultValue?: boolean): this;
  slider(label: string, min: number, max: number, step?: number, defaultValue?: number): this;
  dropdown(label: string, options: string[], defaultIndex?: number): this;
  show(player: Player): Promise<ModalFormResult>;
}


interface OnOptions {
  direction?: Direction | "both";
  side?: Side | "both";
}
interface SendOptions {
  direction?: Direction;
  side?: Side;
  player?: number | "all";
}

interface PacketEvent {
  readonly id: number;
  readonly name: string;
  readonly direction: Direction;
  readonly side: Side;
  readonly player: number | null;
  readonly connection: "rakNet" | "address" | "address6" | "netherNet" | "invalid" | number | null;
  readonly size: number;
  readonly body: Uint8Array;
  readonly packet: PacketBase;
  readonly view: PacketBase;
  cancel(): void;
  replace(value: Bytes): void;
}

type PacketTarget = string | number | Array<string | number> | "*";

declare const packet: {
  on(target: PacketTarget, callback: (event: PacketEvent) => void, options?: OnOptions): number;
  off(handle: number): boolean;
  send(target: string | number, body: Bytes, options?: SendOptions): true;
  send(packet: PacketBase, options?: SendOptions): true;
  name(id: number): string;
  id(name: string): number;
  readonly types: { readonly [name: string]: PacketClass<any> };
};
declare const Packets: { readonly [name: string]: number };

declare class PacketBase {
  tail: Uint8Array;
  toBytes(): Uint8Array;
  clone(): this;
  send(options?: SendOptions): true;
  fingerprint(): string;
  toJSON(): unknown;
}
interface PacketClass<T extends PacketBase> {
  new (values?: Partial<T>): T;
  decode(bytes: Bytes): T;
  readonly id: number | undefined;
  readonly packetName: string;
}

declare class RawPacket extends PacketBase {
  readonly id: number;
  readonly name: string;
  body: Uint8Array;
  reader(): BinaryReader;
}

declare class TextPacket extends PacketBase {
  needsTranslation: boolean;
  type: TextType;
  sender: string;
  message: string;
  parameters: string[];
  xuid: string;
  platformChatId: string;
  filteredMessage: string | null;
  constructor(values?: Partial<TextPacket>);
  static decode(bytes: Bytes): TextPacket;
  static readonly id: number | undefined;
  static readonly Type: Readonly<Record<string, number>>;
  static chat(message: string, sender?: string): TextPacket;
  static whisper(message: string, sender?: string): TextPacket;
  static announcement(message: string, sender?: string): TextPacket;
  static raw(message: string): TextPacket;
  static tip(message: string): TextPacket;
  static system(message: string): TextPacket;
  static popup(message: string): TextPacket;
  static translation(key: string, parameters?: string[]): TextPacket;
}

declare class SetTitlePacket extends PacketBase {
  type: "clear" | "reset" | "title" | "subtitle" | "actionbar" | "animationTimes" | "titleJson" | "subtitleJson" | "actionbarJson" | number;
  text: string;
  fadeIn: number;
  stay: number;
  fadeOut: number;
  xuid: string;
  platformOnlineId: string;
  filteredText: string;
  constructor(values?: Partial<SetTitlePacket>);
  static decode(bytes: Bytes): SetTitlePacket;
  static readonly id: number | undefined;
  static title(text: string): SetTitlePacket;
  static subtitle(text: string): SetTitlePacket;
  static actionbar(text: string): SetTitlePacket;
  static times(fadeIn: number, stay: number, fadeOut: number): SetTitlePacket;
  static clear(): SetTitlePacket;
}

interface JwtParts {
  header: any;
  payload: any;
  signature: string;
}
declare class LoginPacket extends PacketBase {
  protocol: number;
  authInfoJson: string;
  clientDataJwt: string;
  readonly authInfo: any;
  readonly chain: JwtParts[];
  readonly clientData: any;
  readonly clientDataHeader: any;
  readonly identity: { name?: string; xuid?: string; uuid?: string; titleId?: string } | null;
  summary(): any;
  setClientData(changes: Record<string, unknown>): this;
  constructor(values?: Partial<LoginPacket>);
  static decode(bytes: Bytes): LoginPacket;
  static readonly id: number | undefined;
}

declare class DisconnectPacket extends PacketBase {
  reason: number;
  message: string | null;
  filteredMessage: string | null;
  constructor(values?: Partial<DisconnectPacket>);
  static decode(bytes: Bytes): DisconnectPacket;
  static readonly id: number | undefined;
  static kick(message: string, reason?: number): DisconnectPacket;
}

interface CommandOrigin {
  type: string;
  uuid: string;
  requestId: string;
  playerId: bigint;
}
declare class CommandRequestPacket extends PacketBase {
  command: string;
  origin: CommandOrigin;
  isInternal: boolean;
  version: string;
  constructor(values?: Partial<CommandRequestPacket>);
  static decode(bytes: Bytes): CommandRequestPacket;
  static readonly id: number | undefined;
  static run(command: string, options?: { like?: CommandRequestPacket }): CommandRequestPacket;
}

declare class ModalFormRequestPacket extends PacketBase {
  formId: number;
  formData: string;
  json: any;
  constructor(values?: Partial<ModalFormRequestPacket>);
  static decode(bytes: Bytes): ModalFormRequestPacket;
  static readonly id: number | undefined;
  static show(formId: number, form: object | string): ModalFormRequestPacket;
}
declare class ModalFormResponsePacket extends PacketBase {
  formId: number;
  formData: string | null;
  cancelReason: number | null;
  json: any;
  constructor(values?: Partial<ModalFormResponsePacket>);
  static decode(bytes: Bytes): ModalFormResponsePacket;
  static readonly id: number | undefined;
  static readonly CancelReason: { readonly closed: 0; readonly userBusy: 1 };
  static response(formId: number, answer: unknown): ModalFormResponsePacket;
  static cancel(formId: number, cancelReason?: number): ModalFormResponsePacket;
}


interface Codec<T> {
  read(reader: BinaryReader): T;
  write(writer: BinaryWriter, value: T): void;
}
declare const Types: {
  readonly bool: Codec<boolean>;
  readonly u8: Codec<number>; readonly i8: Codec<number>;
  readonly u16: Codec<number>; readonly i16: Codec<number>;
  readonly u32: Codec<number>; readonly i32: Codec<number>;
  readonly u16be: Codec<number>; readonly u32be: Codec<number>; readonly i32be: Codec<number>;
  readonly u64: Codec<bigint>; readonly i64: Codec<bigint>;
  readonly f32: Codec<number>; readonly f64: Codec<number>;
  readonly varuint: Codec<number>; readonly varint: Codec<number>;
  readonly varuint64: Codec<bigint>; readonly varint64: Codec<bigint>;
  readonly string: Codec<string>;
  readonly bytes: Codec<Uint8Array>;
  readonly uuid: Codec<string>;
  readonly vec3: Codec<{ x: number; y: number; z: number }>;
  readonly blockPos: Codec<{ x: number; y: number; z: number }>;
  array<T>(element: Codec<T>, count?: Codec<number>): Codec<T[]>;
  optional<T>(element: Codec<T>): Codec<T | null>;
  enum(base: Codec<number>, names: Record<string, number>): Codec<string | number>;
  struct<T extends Record<string, Codec<any>>>(fields: T): Codec<{ [K in keyof T]: T[K] extends Codec<infer V> ? V : never }>;
};

interface PacketSpec<T> {
  fields?: { [K in keyof T]?: Codec<T[K]> };
  defaults?: () => Partial<T>;
  read?(reader: BinaryReader, packet: T): void;
  write?(writer: BinaryWriter, packet: T): void;
}
declare function definePacket<T = any>(name: string, spec: PacketSpec<T>): PacketClass<PacketBase & T>;


declare class BinaryReader {
  constructor(bytes: Bytes);
  pos: number;
  readonly remaining: number;
  readonly eof: boolean;
  u8(): number; i8(): number; u16(): number; i16(): number; u32(): number; i32(): number;
  u16be(): number; u32be(): number; i32be(): number;
  u64(): bigint; i64(): bigint; f32(): number; f64(): number; bool(): boolean;
  varuint(): number; varint(): number; varuint64(): bigint; varint64(): bigint;
  string(): string;
  bytes(count: number): Uint8Array;
  rest(): Uint8Array;
  skip(count: number): this;
}
declare class BinaryWriter {
  readonly length: number;
  u8(value: number): this; i8(value: number): this; u16(value: number): this; i16(value: number): this;
  u32(value: number): this; i32(value: number): this; u16be(value: number): this; u32be(value: number): this; i32be(value: number): this;
  u64(value: bigint | number): this; i64(value: bigint | number): this; f32(value: number): this; f64(value: number): this;
  bool(value: boolean): this;
  varuint(value: number): this; varint(value: number): this; varuint64(value: bigint | number): this; varint64(value: bigint | number): this;
  string(text: string): this;
  bytes(value: Bytes): this;
  toBytes(): Uint8Array;
}

declare function hex(bytes: Bytes, limit?: number): string;
declare function unhex(text: string): Uint8Array;
declare const base64: {
  decode(text: string): Uint8Array;
  encode(bytes: Bytes, options?: { url?: boolean }): string;
};
declare const jwt: { decode(token: string): JwtParts };
declare const utf8: { encode(text: string): Uint8Array; decode(bytes: Bytes): string };



type BossColor = "pink" | "blue" | "red" | "green" | "yellow" | "purple" | "rebeccaPurple" | "white";

declare class BossBar {
  refresh(): this;
  constructor(options?: { title?: string; percent?: number; color?: BossColor; actorId?: bigint | number });
  readonly actorId: bigint | null;
  title: string;
  percent: number;
  color: BossColor;
  readonly targets: Player[];
  show(target: Player | Host | Client): this;
  hide(target?: Player | Host | Client): this;
  remove(): this;
}


declare const CommandPermissionLevel: { readonly Any: 0; readonly GameDirectors: 1; readonly Admin: 2; readonly Host: 3; readonly Owner: 4 };
declare const CustomCommandStatus: { readonly Success: 0; readonly Failure: 1 };
declare const CustomCommandParamType: {
  readonly Boolean: "Boolean"; readonly Integer: "Integer"; readonly Float: "Float"; readonly String: "String";
  readonly EntitySelector: "EntitySelector"; readonly PlayerSelector: "PlayerSelector"; readonly Location: "Location";
  readonly BlockType: "BlockType"; readonly ItemType: "ItemType"; readonly Enum: "Enum"; readonly Message: "Message";
};
type CustomCommandParamTypeName = keyof typeof CustomCommandParamType;

interface CustomCommandParameter {
  name: string;
  type: CustomCommandParamTypeName;
  enumName?: string;
}
interface CustomCommand {
  name: string;
  description?: string;
  permissionLevel?: number;
  mandatoryParameters?: CustomCommandParameter[];
  optionalParameters?: CustomCommandParameter[];
}
interface CustomCommandOrigin {
  readonly sourceType: "Entity";
  readonly sourceEntity: Player;
}
interface CustomCommandResult {
  status: number;
  message?: string;
}
type CustomCommandCallback = (origin: CustomCommandOrigin, ...args: any[]) => CustomCommandResult | void | Promise<CustomCommandResult | void>;

interface CustomCommandRegistry {
  registerEnum(name: string, values: string[]): void;
  registerCommand(command: CustomCommand, callback: CustomCommandCallback): void;
  unregisterCommand(name: string): boolean;
  hideCommand(name: string, options?: { block?: boolean }): void;
  showCommand(name: string): boolean;
}
interface StartupEvent {
  readonly customCommandRegistry: CustomCommandRegistry;
}

interface Vec3 { x: number; y: number; z: number }
interface ItemStack { networkId: number; count: number; metadata: number; stackId: number | null; blockRuntimeId: number; userData: Uint8Array }

interface CommandParameter {
  name: string;
  type?: string | number;
  optional?: boolean;
  enum?: string[];
  enumName?: string;
  softEnum?: string;
  options?: number;
  symbol?: number;
}
interface CommandDefinition {
  name: string;
  description?: string;
  permission?: "any" | "gameDirectors" | "admin" | "host" | "owner" | "internal" | string;
  flags?: number;
  aliases?: string[];
  overloads?: CommandParameter[][];
}


declare class InventoryTransactionPacket extends PacketBase {
  legacyRequestId: number;
  legacySetItemSlots: { containerId: number; slots: number[] }[] | null;
  transactionType: "normal" | "inventoryMismatch" | "itemUse" | "itemUseOnActor" | "itemRelease" | number;
  actions: object[];
  runtimeId: bigint;
  actionType: "interact" | "attack" | "itemInteract" | number;
  slot: number;
  hand: number;
  item: ItemStack;
  fromPosition: Vec3;
  hitPosition: Vec3;
  detailsRead: boolean;
  static attack(target: bigint | number, values?: Partial<InventoryTransactionPacket>): InventoryTransactionPacket;
  static interact(target: bigint | number, values?: Partial<InventoryTransactionPacket>): InventoryTransactionPacket;
}
declare class PlayerActionPacket extends PacketBase {
  runtimeId: bigint;
  action: string | number;
  blockPosition: { x: number; y: number; z: number };
  resultPosition: { x: number; y: number; z: number };
  face: number;
  static missedSwing(runtimeId?: bigint): PlayerActionPacket;
}
declare class PlayerAuthInputPacket extends PacketBase {
  rotation: { x: number; y: number };
  position: Vec3;
  moveVector: { x: number; y: number };
  headRotation: number;
  inputData: bigint;
  readonly flags: (string | number)[];
  has(flag: string | number): boolean;
  set(flag: string | number, on?: boolean): this;
  complete: boolean;
  inputMode: number; playMode: number; interactionModel: number;
  interactRotation: { x: number; y: number };
  clientTick: bigint;
  posDelta: Vec3;
}
declare class BossEventPacket extends PacketBase {
  targetActorId: bigint;
  eventType: "add" | "playerAdded" | "remove" | "playerRemoved" | "updatePercent" | "updateName" | "updateProperties" | "updateStyle" | "query";
  name: string; filteredName: string; healthPercent: number; color: BossColor;
  darkenScreen: number; playerId: bigint;
  static add(id: bigint | number, options?: { name?: string; percent?: number; color?: BossColor }): BossEventPacket;
  static remove(id: bigint | number): BossEventPacket;
  static updatePercent(id: bigint | number, percent: number, state?: { name?: string; percent?: number; color?: string }): BossEventPacket;
  static updateName(id: bigint | number, name: string): BossEventPacket;
  static updateStyle(id: bigint | number, color: BossColor): BossEventPacket;
}
declare class AvailableCommandsPacket extends PacketBase {
  enumValues: string[]; chainedSubcommandValues: string[]; postFixes: string[];
  enumData: { name: string; values: number[] }[];
  chainedSubcommandData: { name: string; subcommandValues: { firstValue: number; secondValue: number }[] }[];
  commands: { name: string; description: string; flags: number; permissionLevel: string; aliasEnum: number; chainedSubcommandIndexes: number[];
    overloads: { isChaining: boolean; parameters: { name: string; parseSymbol: number; isOptional: boolean; options: number }[] }[] }[];
  softEnums: { enumName: string; enumOptions: string[] }[];
  constraints: { enumValueSymbol: number; enumSymbol: number; constraintIndices: number[] }[];
  addCommand(definition: CommandDefinition): this;
  addSoftEnum(name: string, words: string[]): this;
  static build(commands: CommandDefinition[], options?: { softEnums?: { [name: string]: string[] } }): AvailableCommandsPacket;
}
declare class UpdateSoftEnumPacket extends PacketBase {
  enumName: string; values: string[]; updateType: "add" | "remove" | "replace";
  static add(name: string, values: string[]): UpdateSoftEnumPacket;
  static remove(name: string, values: string[]): UpdateSoftEnumPacket;
  static replace(name: string, values: string[]): UpdateSoftEnumPacket;
}
declare class MobEquipmentPacket extends PacketBase {
  runtimeId: bigint; item: ItemStack; slot: number; selectedSlot: number; containerId: number;
}
declare function emptyItem(): ItemStack;
