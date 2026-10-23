# APK Lister — Total Commander Lister plugin (WLX) for Android packages

![APK Lister](docs/screenshot.png)

[Русский](#русский) · [English](#english)

---

## Русский

**APK Lister** — плагин просмотрщика (Lister, F3 / Ctrl+Q) для Total Commander, показывающий максимум технической информации об Android‑пакетах:
`.apk`, `.xapk`, `.apks`, `.apkm`, `.aab` (Android App Bundle) и `.apex`.

Написан на чистом C++/Win32 без внешних зависимостей: собственные парсеры ZIP/zip64, бинарного XML (AXML), `resources.arsc`, protobuf‑манифеста/ресурсов aapt2 (AAB), JSON‑манифестов бандлов, DEX и ELF. Файл отображается в память (memory‑mapped), большие APK открываются за доли секунды.

### Что показывает

Одна страница со сводкой по секциям. В заголовке — иконка, название, пакет, версия, диапазон API и **архитектуры (ABI)**.

- FILE: размер, MD5 / SHA‑1 / SHA‑256;
- PACKAGE: имя пакета, метка (включая локализованные), versionName/Code, **Architecture** — список ABI с разрядностью (например, `arm64-v8a (64-bit ARM)`; без нативного кода — `universal (no native code)`; для бандлов учитываются ABI из config‑сплитов и всех модулей AAB), min/target/max/compile SDK с названиями версий Android, installLocation, sharedUserId, класс Application, иконка, тема и все флаги `<application>` (debuggable, allowBackup, usesCleartextTraffic, networkSecurityConfig, extractNativeLibs, …) с умолчаниями;
- PERMISSIONS с уровнем защиты (dangerous / signature / …), объявленные разрешения, FEATURES;
- meta‑data, uses-library, `<queries>`, прочие элементы манифеста;
- NATIVE LIBRARIES: ABI, размеры, выравнивание ELF‑сегментов (проверка совместимости с 16 KB page size), версия NDK, выравнивание несжатых .so в zip;
- DEX: число классов/методов/полей/строк, версия формата, маркеры R8/D8 (min‑api, режим компиляции), обнаруженные библиотеки;
- FRAMEWORKS & TECHNOLOGIES: Flutter, React Native, Unity, Xamarin/.NET MAUI, Kotlin, Compose, Cordova, протекторы/обфускаторы и т.п.;
- BUILD INFO: версия AGP, `META-INF/*.version`, `*.properties`, информация о VCS;
- RESOURCES: локали, плотности, конфигурации; ZIP STRUCTURE;
- для контейнеров (XAPK/APKS/APKM/AAB): список сплитов с классификацией (base / ABI / язык / плотность / feature), манифест бандла, BundleConfig, затем полный анализ base APK.

Весь текст можно выделять и копировать (Ctrl+A, Ctrl+C / Ctrl+Ins), работает поиск TC (F7 / F3 «найти далее», с учётом регистра, целых слов и обратного направления). В режиме эскизов (Ctrl+F1) TC показывает иконку приложения.

Подписи и компоненты (activities/services/…) в версии 0.1.1 намеренно не показываются, чтобы сводка оставалась компактной.

### Установка

Откройте в Total Commander архив `apklister-0.1.1.zip` (Enter) — TC предложит установить плагин по `pluginst.inf`.
Вручную: *Конфигурация → Настройка → Плагины → Lister (WLX) → Добавить*, выберите `apklister.wlx` (64‑битный TC сам подхватит `apklister.wlx64` из той же папки).

Строка определения: `EXT="APK" | EXT="XAPK" | EXT="APKS" | EXT="APKM" | EXT="AAB" | EXT="APEX"`.

### Клавиши

| Клавиша | Действие |
|---|---|
| Ctrl+A, Ctrl+C, Ctrl+Ins | выделить всё / копировать |
| F7, F3 | поиск средствами TC |
| Esc, 1–7, N/P и остальные | передаются Total Commander (режимы просмотра Lister работают как обычно) |

### Сборка

Нужен mingw‑w64 (кросс‑компиляция под Linux или MSYS2):

```sh
make            # build/apklister.wlx, build/apklister.wlx64, apkinfo.exe, apkinfo32.exe, testhost*.exe
make dist       # build/apklister-0.1.1.zip (wlx, wlx64, pluginst.inf, README.md, LICENSE)
make native     # build/apkinfo-native — консольная версия анализатора для Linux
make asan       # то же с AddressSanitizer/UBSan (для фаззинга)
```

libgcc/libstdc++ линкуются статически, DLL зависят только от системных библиотек Windows.

### Тестирование

- `apkinfo [-m] [-f] [-a] [--nohash] [--icon out.png] file` — тот же анализатор в консоли (сводка по умолчанию; `-m` — декодированный AndroidManifest.xml, `-f` — список файлов архива).
- `testhost.exe plugin.wlx64 file [search] [--preview out.bmp]` (и `testhost32.exe` для `apklister.wlx`) — минимальный хост, имитирующий TC (работает и под Wine).
- `tools/fuzz.py` — мутационный фаззер для ASan‑сборки.

Результаты сверены с `aapt2 dump badging` на реальных APK (F‑Droid, Termux, Binary Eye, Editor) и на бандлах, сгенерированных bundletool 1.17.2 (`samples/demo.*`).
Большие реальные образцы в репозиторий не включены (их можно скачать с f-droid.org).

### Известные ограничения

- подписи и компоненты не показываются;
- `toc.pb` в APKS не декодируется; зашифрованные APKM не поддерживаются;
- иконки WebP показываются только при наличии WebP‑кодека WIC (Windows 10+); adaptive/vector‑иконки заменяются ближайшим PNG;
- нет тёмной темы; хеши файла считаются синхронно (на файлах в сотни МБ — около секунды);
- 32‑битная версия не открывает файлы больше ~1.5 ГБ;
- проверено в тестовом хосте под Wine, но ещё не в настоящем Total Commander.

### Лицензия

Предлагается **GPL-2.0-or-later** (см. `LICENSE`) — это предложение, лицензию можно сменить до публикации.

---

## English

**APK Lister** is a Lister (F3 / Ctrl+Q) plugin for Total Commander that shows as much technical information as possible about Android packages:
`.apk`, `.xapk`, `.apks`, `.apkm`, `.aab` (Android App Bundle) and `.apex`.

Pure C++/Win32, no external dependencies: own parsers for ZIP/zip64, binary XML (AXML), `resources.arsc`, aapt2 protobuf manifest/resources (AAB), bundle JSON manifests, DEX and ELF. Files are memory‑mapped; large APKs open in a fraction of a second.

### What it shows

A single summary page. The header shows the icon, name, package, version, API range and **architectures (ABIs)**.

Sections: package identity, labels (incl. localized), versions, **Architecture** (ABIs with bitness, e.g. `arm64-v8a (64-bit ARM)`; `universal (no native code)` when there is none; bundles aggregate ABIs from config splits / all AAB modules), SDK levels with Android release names, all `<application>` flags with defaults; permissions with protection levels, features; meta‑data, libraries, `<queries>`; native libraries per ABI with 16 KB page‑size alignment check, NDK version, zip alignment; DEX statistics, R8/D8 markers, detected libraries; frameworks (Flutter, React Native, Unity, Xamarin/MAUI, Kotlin, Compose, Cordova, protectors…); build info (AGP version, `META-INF/*.version`, VCS info); resources (locales, densities, configs); ZIP structure. For containers: split list with classification, bundle manifest / BundleConfig, then full analysis of the base APK. Signatures and components are intentionally not shown in 0.1.1.

All text is selectable and copyable (Ctrl+A, Ctrl+C / Ctrl+Ins); TC search (F7 / F3) is supported, all other keys (Esc, Lister view modes 1–7, N/P…) go to Total Commander, and thumbnails (app icon) in TC's thumbnail view.

### Install

Open `apklister-0.1.1.zip` in Total Commander and confirm installation (uses `pluginst.inf`), or add `apklister.wlx` manually under *Configuration → Options → Plugins → Lister (WLX)*.

### Build

```sh
make          # 32/64-bit plugin, apkinfo CLI, test hosts (mingw-w64)
make dist     # release zip
make native   # Linux CLI build;  make asan  # sanitizer build for fuzzing
```

### Testing

`apkinfo` CLI (same analyzer), `testhost.exe` / `testhost32.exe` (minimal TC‑like host, works under Wine), `tools/fuzz.py` (mutation fuzzer). Output cross‑checked against `aapt2`.

### Known limitations

Signatures and components are not shown; `toc.pb` not decoded; encrypted APKM unsupported; WebP icons need a WIC WebP codec; adaptive/vector icons fall back to PNG; no dark mode; hashing is synchronous; 32‑bit build limited to ~1.5 GB files; not yet tested in a real Total Commander.

### License

Proposed: **GPL-2.0-or-later** (see `LICENSE`). This is a proposal and can be changed before publishing.
