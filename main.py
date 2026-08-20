"""Telegram-бот: прокси-ссылки -> YAML для Clash Meta (Mihomo).

Хендлеры:
  /start                  приветствие + кнопка «Инструкция»
  text (не команда)       ссылки прямо в чате
  document (.txt)         ссылки файлом

Поток обработки: «⏳ Анализ данных...» -> прогресс конвертации
[▓▓▓░░░░░░░] -> итоговая статистика + файл clash_meta_proxies.yaml.
"""
import asyncio
import io
import logging
import time
from collections.abc import Callable

from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import CommandStart
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

from config import BOT_TOKEN, LOG_LEVEL, MAX_PROXIES
from converter import build_yaml, parse_batch

logger = logging.getLogger(__name__)
router = Router()

BAR_FULL, BAR_EMPTY = "▓", "░"

# Ожидающие ответа на вопрос про дубликаты: (chat_id, status_message_id) -> Future
_pending: dict[tuple[int, int], "asyncio.Future[bool]"] = {}


def _dedupe_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(text="✅ Да", callback_data="dedupe_yes"),
                InlineKeyboardButton(text="❌ Нет", callback_data="dedupe_no"),
            ]
        ]
    )


@router.callback_query(F.data.in_({"dedupe_yes", "dedupe_no"}))
async def cb_dedupe(callback: CallbackQuery) -> None:
    """Ответ на вопрос про дубликаты IP: будит ожидающий конвейер."""
    if callback.message is not None:
        fut = _pending.pop((callback.message.chat.id, callback.message.message_id), None)
        if fut is not None and not fut.done():
            fut.set_result(callback.data == "dedupe_yes")
    await callback.answer()

START_TEXT = (
    "👋 <b>Привет! Я — конвертер прокси-ссылок в YAML для Clash Meta (Mihomo).</b>\n\n"
    "🚀 <b>Поддерживаемые протоколы:</b>\n"
    "• <b>VLESS</b> (Reality, TLS, TCP, WS, gRPC, H2, HTTPUpgrade, XHTTP)\n"
    "• <b>VMess</b> (v2rayN base64 JSON / URI)\n"
    "• <b>Trojan</b> (TLS, Reality, WS, gRPC)\n"
    "• <b>Shadowsocks (SS) &amp; SSR</b> (SIP002, Legacy, плагины obfs / v2ray-plugin)\n"
    "• <b>Hysteria 2 (hy2)</b>\n"
    "• <b>TUIC</b>\n"
    "• <b>SOCKS5 / SOCKS</b>\n"
    "• <b>HTTP / HTTPS</b>\n"
    "• <b>WireGuard (wg)</b>\n\n"
    "📤 Просто отправьте ссылки в чат (по одной на строку) или файлом <code>.txt</code> — и я сформирую <code>clash_meta_proxies.yaml</code>.\n\n"
    "👇 Подробнее — в инструкции."
)

HELP_TEXT = (
    "📖 <b>Инструкция</b>\n\n"
    "1️⃣ <b>Текст:</b> отправьте ссылки в чат, каждую с новой строки.\n"
    "2️⃣ <b>Файл:</b> прикрепите файл с расширением <code>.txt</code> — "
    "ссылки внутри будут обработаны автоматически.\n"
    "3️⃣ <b>Результат:</b> пришлю файл <code>clash_meta_proxies.yaml</code> — "
    "секцию <code>proxies</code>, которую можно вставить в ваш Clash-конфиг.\n\n"
    "⚡ <b>Поддерживаются форматы ссылок:</b>\n"
    "<code>vless://</code>, <code>vmess://</code>, <code>trojan://</code>, "
    "<code>ss://</code>, <code>ssr://</code>, <code>hy2://</code> (<code>hysteria2://</code>), "
    "<code>tuic://</code>, <code>socks5://</code>, <code>http://</code>, <code>wireguard://</code>"
)
NO_LINKS_TEXT = (
    "❌ <b>Не найдено ни одной валидной прокси-ссылки.</b>\n\n"
    "Проверьте формат. Пример корректной VLESS-ссылки:\n"
    "<code>vless://UUID@server:443?type=tcp&amp;security=reality&amp;sni=example.com"
    "&amp;fp=chrome&amp;pbk=КЛЮЧ&amp;sid=ID&amp;flow=xtls-rprx-vision#Название</code>\n\n"
    "Отправьте ссылки текстом (по одной на строку) или файлом <code>.txt</code>."
)


def _progress_bar(pct: int) -> str:
    """Рисует полосу прогресса на 10 сегментов: [▓▓▓░░░░░░░]."""
    filled = round(pct / 10)
    return BAR_FULL * filled + BAR_EMPTY * (10 - filled)


def _start_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="📖 Инструкция", callback_data="help")]]
    )


def _back_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[[InlineKeyboardButton(text="◀️ Назад", callback_data="start")]]
    )


@router.message(CommandStart())
async def cmd_start(message: Message) -> None:
    """Приветствие с кнопкой «Инструкция»."""
    await message.answer(START_TEXT, reply_markup=_start_keyboard())


@router.callback_query(F.data == "help")
async def cb_help(callback: CallbackQuery) -> None:
    """Показывает инструкцию по использованию."""
    await callback.message.edit_text(HELP_TEXT, reply_markup=_back_keyboard())
    await callback.answer()


@router.callback_query(F.data == "start")
async def cb_back(callback: CallbackQuery) -> None:
    """Возврат из инструкции к приветствию."""
    await callback.message.edit_text(START_TEXT, reply_markup=_start_keyboard())
    await callback.answer()


@router.message(F.text)
async def handle_text(message: Message) -> None:
    """Любой текст (кроме команд) считаем набором прокси-ссылок."""
    if message.text.startswith("/"):
        return
    await _process_input(message, message.text)


@router.message(F.document)
async def handle_document(message: Message) -> None:
    """Обработка прикреплённого текстового файла (.txt)."""
    doc = message.document
    if not (doc.file_name or "").lower().endswith(".txt"):
        await message.answer(
            "⚠️ Поддерживаются только файлы <code>.txt</code>.\n"
            "Пришлите текстовый файл или просто вставьте ссылки сообщением."
        )
        return
    try:
        file = await message.bot.get_file(doc.file_id)
        buf = io.BytesIO()
        await message.bot.download_file(file.file_path, destination=buf)
        text = buf.getvalue().decode("utf-8", errors="replace")
    except Exception as exc:
        logger.exception("Не удалось скачать файл %s", doc.file_name)
        await message.answer(f"❌ Не удалось прочитать файл: {exc}")
        return
    await _process_input(message, text)


async def _progress_updater(
    status: Message, queue: "asyncio.Queue[tuple[int, int, int]]"
) -> None:
    """Ест очередь прогресса и редактирует сообщение со статусом.

    Позиция бара — реальный процент обработанных строк (их присылает
    parse_batch после каждой порции). Пачки шагов схлопываются в один
    эдит, а правки троттлятся до одной в 0.3 c: Telegram не любит
    частые правки одного сообщения, а для быстрых файлов бар не должен
    висеть — 100% показывается сразу, как только работа сделана.
    """
    last_shown, last_edit = -1, 0.0
    while True:
        pct, processed, total = await queue.get()
        # выхватываем всё, что успело накопиться, показываем последнее
        while not queue.empty():
            pct, processed, total = max((pct, processed, total), (await queue.get()))
        now = time.monotonic()
        wait = 0.3 - (now - last_edit)  # троттлинг правок сообщения
        if wait > 0:
            await asyncio.sleep(wait)
        if pct - last_shown >= 5 or pct >= 100:  # мелкие шаги пропускаем
            await status.edit_text(
                f"⚙️ Конвертация ссылок в YAML [{_progress_bar(pct)}] {pct}%"
                f" · строк {processed}/{total}"
            )
            last_shown, last_edit = pct, time.monotonic()
        if pct >= 100:
            return


async def _process_input(message: Message, text: str) -> None:
    """Основной конвейер: анализ -> прогресс конвертации -> статистика + файл."""
    status = await message.answer("⏳ Анализ данных...")
    try:
        # Прогресс привязан к реальной обработке: parse_batch дробит вход
        # на порции строк и сообщает процент после каждой. Для 2-3 ссылок
        # работы реально на миллисекунды, поэтому бар добегает до 100%
        # почти сразу — это не имитация, просто работы мало.
        queue: asyncio.Queue[tuple[int, int, int]] = asyncio.Queue()
        updater = asyncio.create_task(_progress_updater(status, queue))

        def on_progress(pct: int, processed: int, total: int) -> None:
            queue.put_nowait((pct, processed, total))

        result = await parse_batch(text, on_progress=on_progress)
        queue.put_nowait((100, result.total_lines, result.total_lines))
        await updater

        if not result.proxies:
            await status.edit_text(NO_LINKS_TEXT)
            return

        total_parsed = result.ok
        removed_dups = 0

        # Вопрос про дубликаты IP: одинаковый server у разных прокси.
        dup_ips = total_parsed - len({p["server"] for p in result.proxies})
        if dup_ips > 0:
            fut: asyncio.Future[bool] = asyncio.get_running_loop().create_future()
            _pending[(message.chat.id, status.message_id)] = fut
            await status.edit_text(
                f"🔍 Найдено дубликатов IP-адресов: <b>{dup_ips}</b>.\n\n"
                "Убрать их из файла (оставить по одному прокси на сервер)?",
                reply_markup=_dedupe_keyboard(),
            )
            try:
                remove_dups = await asyncio.wait_for(fut, timeout=60)
            except asyncio.TimeoutError:
                remove_dups = False
                await status.edit_text(
                    "⏰ Не дождался ответа — оставляю дубликаты.", reply_markup=None
                )
            finally:
                _pending.pop((message.chat.id, status.message_id), None)
            if remove_dups:
                seen_servers: set[str] = set()
                unique = []
                for p in result.proxies:
                    if p["server"] not in seen_servers:
                        seen_servers.add(p["server"])
                        unique.append(p)
                removed_dups = len(result.proxies) - len(unique)
                result.proxies = unique
                result.ok = len(unique)

        # FLClash не тянет десятки тысяч нод — режем до MAX_PROXIES
        # и честно пишем об этом в статистике.
        if result.ok > MAX_PROXIES:
            result.proxies = result.proxies[:MAX_PROXIES]
            result.ok = len(result.proxies)  # сколько реально попало в файл

        yaml_text = await asyncio.to_thread(build_yaml, result.proxies)
        stats = (
            "✅ <b>Готово!</b> Файл <code>clash_meta_proxies.yaml</code> сформирован.\n\n"
            f"📥 Получено строк: <b>{result.total_lines}</b>\n"
            f"✅ Успешно обработано прокси: <b>{total_parsed}</b>\n"
            f"❌ Пропущено/Ошибки: <b>{result.skipped}</b>"
        )
        if removed_dups:
            stats += f"\n🗑️ Удалено дубликатов IP: <b>{removed_dups}</b>"
        if result.ok < total_parsed - removed_dups:
            stats += f"\n✂️ <b>Показано {result.ok} из {total_parsed - removed_dups}</b> (лимит {MAX_PROXIES} — \
FLClash не тянет больше)"
        await status.edit_text(stats)
        await message.answer_document(
            BufferedInputFile(yaml_text.encode("utf-8"), filename="clash_meta_proxies.yaml"),
            caption="📄 Готовый YAML — секция <code>proxies</code> для Clash Meta",
        )
    except Exception as exc:
        logger.exception("Ошибка обработки входящих данных")
        await status.edit_text(f"❌ Внутренняя ошибка: {exc}")


async def main() -> None:
    """Точка входа: сборка Dispatcher и запуск long-polling."""
    bot = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher()
    dp.include_router(router)
    await bot.delete_webhook(drop_pending_updates=True)
    logger.info("Бот запущен, начинаю polling")
    await dp.start_polling(bot)


if __name__ == "__main__":
    logging.basicConfig(
        level=LOG_LEVEL,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logging.getLogger(__name__).info("Бот остановлен")
