import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';
import 'package:process_run/shell.dart';

import '../model/stats.dart';
import '../wireguard_flutter_platform_interface.dart';

class WireGuardFlutterLinux extends WireGuardFlutterInterface {
  String? name;
  File? configFile;

  VpnStage _stage = VpnStage.noConnection;
  final _stageController = StreamController<VpnStage>.broadcast();
  void _setStage(VpnStage stage) {
    _stage = stage;
    _stageController.add(stage);
  }

  final shell = Shell(runInShell: true, verbose: kDebugMode);

  @override
  Future<void> initialize({required String interfaceName}) async {
    name = interfaceName.replaceAll(' ', '_');
    await refreshStage();
  }

  Future<String> get filePath async {
    // final tempDir = await getTemporaryDirectory();
    return '/etc/wireguard${Platform.pathSeparator}$name.conf';
  }

  @override
  Future<void> startVpn({required String serverAddress, required String wgQuickConfig, required String providerBundleIdentifier}) async {
    final isAlreadyConnected = await isConnected();
    if (!isAlreadyConnected) {
      _setStage(VpnStage.preparing);
    } else {
      debugPrint('Already connected');
    }

    try {
      // shell.run('echo -e \'${wgQuickConfig}\' | sudo tee ${await filePath} > /dev/null');
      final process = await Process.start('sudo', ['tee', '${await filePath}']);
      process.stdin.write(wgQuickConfig);
      await process.stdin.close();
      var exitCode = await process.exitCode;
      debugPrint('wrote wg config file to ${await filePath} with exit code of ${exitCode}');
      // configFile = await File(await filePath).create();
      // await configFile!.writeAsString(wgQuickConfig);
    } on PathAccessException {
      debugPrint('Denied to write file. Trying to start interface');
      if (isAlreadyConnected) {
        return _setStage(VpnStage.connected);
      }

      try {
        await shell.run('sudo wg-quick up $name');
        ProcessSignal.sigint.watch().listen((_) {
          shell.run('sudo wg-quick down $name');
        });
        ProcessSignal.sigterm.watch().listen((_) {
          shell.run('sudo wg-quick down $name');
        });
      } catch (_) {
      } finally {
        _setStage(VpnStage.denied);
      }
    }

    if (!isAlreadyConnected) {
      _setStage(VpnStage.connecting);
      await shell.run('sudo wg-quick up ${configFile?.path ?? await filePath}');
      ProcessSignal.sigint.watch().listen((_) {
        shell.run('sudo wg-quick down $name');
      });
      ProcessSignal.sigterm.watch().listen((_) {
        shell.run('sudo wg-quick down $name');
      });
      _setStage(VpnStage.connected);
    }
  }

  @override
  Future<void> stopVpn() async {
    assert((await isConnected()), 'Bad state: vpn has not been started. Call startVpn');
    _setStage(VpnStage.disconnecting);
    try {
      await shell.run('sudo wg-quick down ${configFile?.path ?? (await filePath)}');
    } catch (e) {
      await refreshStage();
      rethrow;
    }
    await refreshStage();
  }

  @override
  Future<VpnStage> stage() async => _stage;

  @override
  Stream<VpnStage> get vpnStageSnapshot => _stageController.stream;

  @override
  Future<void> refreshStage() async {
    if (await isConnected()) {
      _setStage(VpnStage.connected);
    } else if (name == null) {
      _setStage(VpnStage.waitingConnection);
    } else if (configFile == null) {
      _setStage(VpnStage.noConnection);
    } else {
      _setStage(VpnStage.disconnected);
    }
  }

  @override
  Future<bool> isConnected() async {
    assert(name != null, 'Bad state: not initialized. Call "initialize" before calling this command');
    final processResultList = await shell.run('sudo wg');
    final process = processResultList.first;
    return process.outLines.any((line) => line.trim() == 'interface: $name');
  }

  @override
  Future<Stats?> getStats() async {
    if (await isConnected()) {
      return null;
    }

    final processResultList = await shell.run('sudo wg show $name');
    final process = processResultList.first;
    final lines = process.outLines;

    if (lines.isEmpty) return null;

    num totalDownload = 0;
    num totalUpload = 0;
    int lastHandshake = 0;

    for (var line in lines) {
      if (line.contains('transfer:')) {
        (totalUpload, totalDownload) = parseTransfer(line);
      }
      if (line.contains('latest handshake:')) {
        var handshakeData = line.split(': ')[1].trim();
        if (handshakeData != '0') {
          // Parse the date and time
          var dateTime = parseWgHandshake(handshakeData);
          if (dateTime != null) {
            lastHandshake = dateTime.millisecondsSinceEpoch;
          }
        }
      }
    }

    return Stats(totalDownload: totalDownload, totalUpload: totalUpload, lastHandshake: lastHandshake);
  }

  /// Parses the "latest handshake" string from `wg show` into a Dart DateTime.
  /// Returns null if the handshake has never happened (or on error).
  DateTime? parseWgHandshake(String handshakeStr) {
    if (handshakeStr.isEmpty || handshakeStr.contains("0")) {
      // Depending on wg version/state, "0" or empty might mean no handshake.
      // Usually, if no handshake occurred, the line is often omitted or 0.
      return null;
    }

    // 1. Handle the "Now" case defined in ago()
    if (handshakeStr.trim() == "Now") {
      return DateTime.now();
    }

    // 2. Handle the "System clock wound backward" error case
    if (handshakeStr.contains("System clock wound backward")) {
      // You might want to throw an error or return null here
      return null;
    }

    // 3. Strip ANSI escape codes (e.g., \x1b[36m) and standard separators
    // The C code uses TERMINAL_FG_CYAN etc.
    final ansiRegex = RegExp(r'\x1B\[[0-9;]*[mK]');
    String cleanStr = handshakeStr.replaceAll(ansiRegex, '');

    // Remove " ago" and standardizing text
    cleanStr = cleanStr.replaceAll(' ago', '').trim();

    // 4. Parse the duration components
    int years = 0;
    int days = 0;
    int hours = 0;
    int minutes = 0;
    int seconds = 0;

    // Regex looks for a number followed by a word (e.g., "2 minutes")
    final regex = RegExp(r'(\d+)\s+([a-zA-Z]+)');
    final matches = regex.allMatches(cleanStr);

    for (final match in matches) {
      final value = int.parse(match.group(1)!);
      final unit = match.group(2)!.toLowerCase();

      // Check startsWith to handle plurals (year/years, day/days)
      if (unit.startsWith('year')) {
        years = value;
      } else if (unit.startsWith('day')) {
        days = value;
      } else if (unit.startsWith('hour')) {
        hours = value;
      } else if (unit.startsWith('minute')) {
        minutes = value;
      } else if (unit.startsWith('second')) {
        seconds = value;
      }
    }

    // 5. Calculate the past date
    // Note: The C code hardcodes a year as 365 days: "years = left / (365 * 24 * 60 * 60);"
    // We must mimic this to get the accurate timestamp back.
    final totalDays = (years * 365) + days;

    final durationAgo = Duration(days: totalDays, hours: hours, minutes: minutes, seconds: seconds);

    return DateTime.now().subtract(durationAgo);
  }

  int _unitToMultiplier(String unit) {
    switch (unit) {
      case 'KiB':
        return 1024;
      case 'MiB':
        return 1024 * 1024;
      case 'GiB':
        return 1024 * 1024 * 1024;
      case 'TiB':
        return 1024 * 1024 * 1024 * 1024;
      default:
        throw ArgumentError('Unknown unit: $unit');
    }
  }

  (int received, int sent) parseTransfer(String line) {
    final regex = RegExp(r'transfer:\s*([\d.]+)\s*(KiB|MiB|GiB|TiB)\s*received,\s*([\d.]+)\s*(KiB|MiB|GiB|TiB)\s*sent');

    final m = regex.firstMatch(line);
    if (m == null) {
      throw FormatException('Could not parse transfer line: $line');
    }

    final recvValue = double.parse(m.group(1)!);
    final recvUnit = m.group(2)!;
    final sentValue = double.parse(m.group(3)!);
    final sentUnit = m.group(4)!;

    final receivedBytes = (recvValue * _unitToMultiplier(recvUnit)).round();
    final sentBytes = (sentValue * _unitToMultiplier(sentUnit)).round();

    return (sentBytes, receivedBytes);
  }
}
