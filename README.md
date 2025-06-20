# 🛡️ AntiRaidBot Open Source

## Обзор проекта

**AntiRaidBot** — это Discord-бот, разработанный с целью защиты серверов от рейдов и несанкционированных действий. В данном репозитории мы показываем отрывки исходного кода и структуру базы данных для лучшего понимания архитектуры бота.

На данный момент бот поддерживает работу на 75 серверах, используя **SQLite3** как основную систему хранения данных. Несмотря на доступность асинхронной версии (aiosqlite), её использование не даёт преимущества в производительности на текущем уровне нагрузки.

---

## 🗂 Структура базы данных

| Таблица | Назначение |
|--------|------------|
| `protection_status` | Хранит информацию о включённой/выключенной защите на сервере |
| `action_limits` | Установленные лимиты по количеству действий в день |
| `premium_codes` | Генерируемые премиум-коды |
| `premium_status` | Информация о премиум-пользователях |
| `blacklisted_roles` | Роли, запрещённые к добавлению |
| `trusted_users` | Список доверенных пользователей |
| `channel_permissions` | Временные разрешения на каналы |
| `server_images` | URL изображений для кастомизации эмбедов |

---

## Пример асинхронной функции

```python
async def interaction_check(self, interaction: discord.Interaction) -> bool:
    if interaction.user.id != self.owner_id:
        embed = discord.Embed(
            title=f"{EMOJI['error']} Ошибка доступа",
            description="Только владелец сервера может управлять настройками!",
            color=SECONDARY_COLOR,
            timestamp=datetime.now()
        )
        embed.set_footer(text="Anti Raid Bot • Ограниченный доступ")
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return False

    guild = interaction.guild
    bot_member = guild.me
    required_permissions = discord.Permissions()
    required_permissions.update(
        manage_roles=True,
        manage_channels=True,
        view_audit_log=True,
        send_messages=True,
        embed_links=True,
        use_application_commands=True
    )

    missing_perms = [
        perm for perm, value in required_permissions if value and not getattr(bot_member.guild_permissions, perm)
    ]
    if missing_perms:
        missing_perms_list = "\n".join([f"- `{PERMISSIONS_RU.get(perm, perm)}`" for perm in missing_perms])
        embed = discord.Embed(
            title=f"{EMOJI['error']} Недостающие права бота",
            description=f"Бот не может выполнить действие, так как ему не хватает следующих прав:\n{missing_perms_list}",
            color=SECONDARY_COLOR,
            timestamp=datetime.now()
        )
        embed.set_footer(text="Anti Raid Bot • Проверка прав")
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return False

    if not is_highest_role(bot_member):
        embed = discord.Embed(
            title=f"{EMOJI['error']} Низкая позиция роли бота",
            description="Роль бота не является самой высокой на сервере. Это ограничивает его способность управлять сервером.",
            color=SECONDARY_COLOR,
            timestamp=datetime.now()
        )
        embed.set_footer(text="Anti Raid Bot • Проверка ролей")
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return False

    return True
```

---

## 📝 Статистика

- **Количество строк кода**: около 3000
- **Проверенная производительность**: работает без проблем на ~75 серверах
- **Используемая БД**: SQLite (без aiosqlite, так как не требуется для текущего масштаба)

---

## 🙌 Поддержка

Если у вас есть вопросы или вы хотите помочь с развитием проекта — присоединяйтесь к нашему серверу поддержки:

[👉 Присоединиться к серверу Discord](https://discord.gg/Qb39HPcpGM)

---

Спасибо за просмотр! Возможно, я буду обновлять этот репозиторий в будущем.

© [Antiraidbot.ru](https://antiraidbot.ru)
