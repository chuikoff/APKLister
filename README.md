# APK Lister — Total Commander Lister plugin (WLX) for Android packages

![Summary tab](docs/screenshot.png)

[Русский](#русский) · [English](#english)

---

## Русский

**APK Lister** — плагин просмотрщика (Lister, F3 / Ctrl+Q) для Total Commander, показывающий максимум технической информации об Android‑пакетах:
`.apk`, `.xapk`, `.apks`, `.apkm`, `.aab` (Android App Bundle) и `.apex`.

Написан на чистом C++/Win32 без внешних зависимостей: собственные парсеры ZIP/zip64, бинарного XML (AXML), `resources.arsc`, protobuf‑манифеста/ресурсов aapt2 (AAB), APK Signing Block (v2/v3/v3.1/v4, source stamp), PKCS#7/X.509, JSON‑манифестов бандлов, DEX и ELF. Файл отображается в память (memory‑mapped), большие APK открываются за доли секунды.

### Что показывает

Три вкладки (переключение клавишами **1 / 2 / 3** или Ctrl+Tab):

1. **Summary** — сводка по секциям:
   - FILE: размер, MD5 / SHA‑1 / SHA‑256;
   - PACKAGE: имя пакета, метка (включая локализованные), versionName/Code, min/target/max/compile SDK с названиями версий Android, installLocation, sharedUserId, класс Application, иконка, тема и все флаги `<application>` (debuggable, allowBackup, usesCleartextTraffic, networkSecurityConfig, extractNativeLibs, …) с умолчаниями;
   - SIGNATURES: схемы v1/v2/v3/v3.1/v4, source stamp, сертификаты (DN, серийный номер, срок действия, алгоритм, размер ключа, отпечатки MD5/SHA‑1/SHA‑256), lineage, признак debug‑сертификата;
   - PERMISSIONS с уровнем защиты (dangerous / signature / …), объявленные разрешения, FEATURES;
   - COMPONENTS: activities, services, receivers, providers с exported, intent‑filters, launcher activity;
   - meta‑data, uses-library, `<queries>`, прочие элементы манифеста;
   - NATIVE LIBRARIES: ABI, размеры, выравнивание ELF‑сегментов (проверка совместимости с 16 KB page size), версия NDK, выравнивание несжатых .so в zip;
   - DEX: число классов/методов/полей/строк, версия формата, маркеры R8/D8 (min‑api, режим компиляции), обнаруженные библиотеки;
   - FRAMEWORKS & TECHNOLOGIES: Flutter, React Native, Unity, Xamarin/.NET MAUI, Kotlin, Compose, Cordova, протекторы/обфускаторы и т.п.;
   - BUILD INFO: версия AGP, `META-INF/*.version`, `*.properties`, информация о VCS;
   - RESOURCES: локали, плотности, конфигурации; ZIP STRUCTURE;
   - для контейнеров (XAPK/APKS/APKM/AAB): список сплитов с классификацией (base / ABI / язык / плотность / feature), манифест бандла, BundleConfig, затем полный анализ base APK.
2. **AndroidManifest.xml** — декодированный манифест в виде читаемого XML (ссылки на ресурсы разрешаются в имена и значения).
3. **Files** — список всех записей архива: метод, размеры, степень сжатия, CRC32, дата, смещение; для контейнеров — также содержимое вложенных APK.

Весь текст можно выделять и копировать (Ctrl+A, Ctrl+C / Ctrl+Ins), работает поиск TC (F7 / F3 «найти далее», с учётом регистра, целых слов и обратного направления). В режиме эскизов (Ctrl+F1) TC показывает иконку приложения.

### Установка

Откройте в Total Commander архив `apklister-0.1.0.zip` (Enter) — TC предложит установить плагин по `pluginst.inf`.
Вручную: *Конфигурация → Настройка → Плагины → Lister (WLX) → Добавить*, выберите `apklister.wlx` (64‑битный TC сам подхватит `apklister.wlx64` из той же папки).

Строка определения: `EXT="APK" | EXT="XAPK" | EXT="APKS" | EXT="APKM" | EXT="AAB" | EXT="APEX"`.

### Клавиши

| Клавиша | Действие |
|---|---|
| 1 / 2 / 3 | вкладки Summary / Manifest / Files |
| Ctrl+Tab, Ctrl+Shift+Tab | следующая / предыдущая вкладка |
| Ctrl+A, Ctrl+C, Ctrl+Ins | выделить всё / копировать |
| F7, F3 | поиск средствами TC |
| Esc, остальные | передаются Total Commander |

Примечание: пока фокус находится в плагине, 1/2/3 переключают вкладки плагина, а не режимы просмотра Lister (1–7).

### Сборка

Нужен mingw‑w64 (кросс‑компиляция под Linux или MSYS2):

```sh
make            # build/apklister.wlx, build/apklister.wlx64, apkinfo.exe, apkinfo32.exe, testhost*.exe
make dist       # build/apklister-0.1.0.zip (wlx, wlx64, pluginst.inf, README.md, LICENSE)
make native     # build/apkinfo-native — консольная версия анализатора для Linux
make asan       # то же с AddressSanitizer/UBSan (для фаззинга)
```

libgcc/libstdc++ линкуются статически, DLL зависят только от системных библиотек Windows.

### Тестирование

- `apkinfo [-m] [-f] [-a] [--nohash] [--icon out.png] file` — тот же анализатор в консоли (вкладки 1/2/3 = по умолчанию / `-m` / `-f`).
- `testhost.exe plugin.wlx64 file [tab] [search] [--preview out.bmp]` — минимальный хост, имитирующий TC (работает и под Wine).
- `tools/fuzz.py` — мутационный фаззер для ASan‑сборки.

Результаты сверены с `aapt2 dump badging` и `apksigner verify --print-certs` на реальных APK (F‑Droid, Termux, Binary Eye, Editor) и на бандлах, сгенерированных bundletool 1.17.2 (`samples/demo.*`).
Большие реальные образцы в репозиторий не включены (их можно скачать с f-droid.org).

### Известные ограничения

- подписи разбираются, но криптографически **не проверяются**;
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

Pure C++/Win32, no external dependencies: own parsers for ZIP/zip64, binary XML (AXML), `resources.arsc`, aapt2 protobuf manifest/resources (AAB), the APK Signing Block (v2/v3/v3.1/v4, source stamp), PKCS#7/X.509, bundle JSON manifests, DEX and ELF. Files are memory‑mapped; large APKs open in a fraction of a second.

### What it shows

Three tabs (switch with **1 / 2 / 3** or Ctrl+Tab):

1. **Summary** — package identity, labels (incl. localized), versions, SDK levels with Android release names, all `<application>` flags with defaults; signature schemes v1–v4 + source stamp, certificates (DN, serial, validity, algorithm, key size, MD5/SHA‑1/SHA‑256), lineage, debug‑cert detection; permissions with protection levels, features, components with exported flags and intent filters; meta‑data, libraries, `<queries>`; native libraries per ABI with 16 KB page‑size alignment check, NDK version, zip alignment; DEX statistics, R8/D8 markers, detected libraries; frameworks (Flutter, React Native, Unity, Xamarin/MAUI, Kotlin, Compose, Cordova, protectors…); build info (AGP version, `META-INF/*.version`, VCS info); resources (locales, densities, configs); ZIP structure. For containers: split list with classification, bundle manifest / BundleConfig, then full analysis of the base APK.
2. **AndroidManifest.xml** — decoded, human‑readable manifest with resolved resource references.
3. **Files** — all archive entries (method, sizes, ratio, CRC32, date, offset), including entries of nested APKs.

All text is selectable and copyable (Ctrl+A, Ctrl+C / Ctrl+Ins); TC search (F7 / F3) is supported, as are thumbnails (app icon) in TC's thumbnail view.

### Install

Open `apklister-0.1.0.zip` in Total Commander and confirm installation (uses `pluginst.inf`), or add `apklister.wlx` manually under *Configuration → Options → Plugins → Lister (WLX)*.

### Build

```sh
make          # 32/64-bit plugin, apkinfo CLI, test hosts (mingw-w64)
make dist     # release zip
make native   # Linux CLI build;  make asan  # sanitizer build for fuzzing
```

### Testing

`apkinfo` CLI (same analyzer), `testhost.exe` (minimal TC‑like host, works under Wine), `tools/fuzz.py` (mutation fuzzer). Output cross‑checked against `aapt2` and `apksigner`.

### Known limitations

No cryptographic signature verification; `toc.pb` not decoded; encrypted APKM unsupported; WebP icons need a WIC WebP codec; adaptive/vector icons fall back to PNG; no dark mode; hashing is synchronous; 32‑bit build limited to ~1.5 GB files; not yet tested in a real Total Commander.

### License

Proposed: **GPL-2.0-or-later** (see `LICENSE`). This is a proposal and can be changed before publishing.
