<?php
/*
Plugin Name: MySQL Security Monitor
Description: 监控数据库是否有异常
Version: 1.4
Author: GuGuan123's Cat
*/

if (!defined('ABSPATH')) exit;

class GG_DB_Security_Monitor {

	const OPTION_NAME = 'gg_db_monitor_settings';
	const RESULT_OPTION_NAME = 'gg_db_monitor_result';

	public function __construct() {
		add_action('admin_menu', array($this, 'create_menu'));
		add_action('gg_db_weekly_check_event', array($this, 'run_security_check_cron'));
		add_action('admin_notices', array($this, 'display_admin_alerts'));

		// 激活与停用
		register_activation_hook(__FILE__, array($this, 'activate'));
		register_deactivation_hook(__FILE__, array($this, 'deactivate'));
		register_uninstall_hook(__FILE__, ['GG_DB_Security_Monitor', 'uninstall']);
	}

	public function run_security_check() {
		global $wpdb;
		$alerts = [];
		$settings = get_option(self::OPTION_NAME);

		// 检测 --skip-grant-tables
		$result = $wpdb->get_row("SHOW VARIABLES LIKE 'skip_grant_tables'");
		if ($result && isset($result->Value) && strtoupper($result->Value) == 'ON') {
			$alerts[] = "🚨 危险：数据库正处于 --skip-grant-tables 模式运行！";
		}

		// 获取白名单逻辑：如果没设置过，就用默认的
		$allowed_db = (isset($settings['allowed_databases']) && is_array($settings['allowed_databases'])) 
					  ? $settings['allowed_databases'] 
					  : array($wpdb->dbname, 'information_schema', 'performance_schema', 'mysql', 'sys');

		// 检测异常数据库
		$unknown_dbs = array_diff($wpdb->get_col("SHOW DATABASES"), $allowed_db);

		if (!empty($unknown_dbs)) $alerts[] = "🔍 检测到异常数据库：" . implode(', ', $unknown_dbs);

		return $alerts;
	}

	public function run_security_check_cron() {
		$alerts = $this->run_security_check();
		if (!empty($alerts)) {
			$settings = get_option(self::OPTION_NAME);
			if (!empty($settings['email_notify'])) {
				$to = get_option('admin_email');
				$subject = '[' . get_bloginfo('name') . '] 数据库异常警报喵！';
				$body = implode(PHP_EOL, $alerts);
				wp_mail($to, $subject, $body);
			}
		}
		update_option(self::RESULT_OPTION_NAME, array('time' => current_time('Y-m-d H:i:s'), 'result' => $alerts));
	}

	// 创建管理页面
	public function create_menu() {
		add_options_page('DB Security', 'DB Security', 'manage_options', 'gg-db-monitor', array($this, 'settings_page'));
	}

	public function settings_page() {
		global $wpdb;
		
		if (isset($_POST['save_settings'])) {
			// 校验 Nonce
			check_admin_referer('gg_db_save_action');
			// 将逗号或换行分隔的字符串转为数组
			$db_input = str_replace(array("\r", "\n"), ',', $_POST['allowed_databases']);
			$db_array = array_filter(array_map('trim', explode(',', $db_input)));
			
			$new_settings = array(
				'email_notify' => isset($_POST['email_notify']) ? 1 : 0,
				'allowed_databases' => array_values(array_unique($db_array))
			);
			update_option(self::OPTION_NAME, $new_settings);
			echo '<div class="updated"><p>设置已保存喵！</p></div>';
		}

		$settings = get_option(self::OPTION_NAME);

		// 每次打开页面都自动运行检测
		$alerts = $this->run_security_check();
		$current_db_list = implode("\n", $settings['allowed_databases'] ?? []);

		?>
		<div class="wrap">
			<h1>🔒 MySQL Security Monitor</h1>
			<p>当前数据库：<code><?php echo esc_html($wpdb->dbname); ?></code></p>
			<hr>

			<h3>当前状态：</h3>
			<?php if (empty($alerts)): ?>
				<div class="notice notice-success inline"><p><strong>✅ 数据库状态一切正常喵~</strong></p></div>
			<?php else: ?>
				<div class="notice notice-error inline">
					<p><strong>⚠️ 发现潜在威胁：</strong></p>
					<ul><?php foreach ($alerts as $alert) echo "<li>".esc_html($alert)."</li>"; ?></ul>
				</div>
			<?php endif; ?>

			<form method="post" style="margin-top: 20px; background: #fff; padding: 20px; border: 1px solid #ccd0d4; border-radius: 5px;">
				<?php wp_nonce_field('gg_db_save_action'); ?>
				<h3>设置</h3>
				<table class="form-table">
					<tr>
						<th scope="row">邮件通知</th>
						<td>
							<label><input type="checkbox" name="email_notify" <?php checked(1, $settings['email_notify'] ?? 0); ?>> 当检测到异常时发送邮件至管理员</label>
						</td>
					</tr>
					<tr>
						<th scope="row">数据库白名单</th>
						<td>
							<textarea name="allowed_databases" rows="6" class="large-text code" placeholder="每行一个数据库名称"><?php echo esc_textarea($current_db_list); ?></textarea>
							<p class="description">在此列出的数据库不会触发警报。当前库：<strong><?php echo $wpdb->dbname; ?></strong></p>
						</td>
					</tr>
				</table>
				<?php submit_button('保存设置', 'primary', 'save_settings'); ?>
			</form>
		</div>
		<?php
	}

	// 后台顶部提醒
	public function display_admin_alerts() {
		// 只在非此插件设置页面显示提醒
		if (isset($_GET['page']) && $_GET['page'] === 'gg-db-monitor') return;
		if (!current_user_can('manage_options')) return;

		// 获取检测报告
		$check_result = get_option(self::RESULT_OPTION_NAME);
		if (!empty($check_result['result'])) {
			?>
			<div class="notice notice-error is-dismissible">
				<p><strong>🚨 数据库安全警告！</strong> 检测到 <?php echo count($check_result['result']); ?> 项异常，请 <a href="<?php echo admin_url('options-general.php?page=gg-db-monitor'); ?>">立即前往处理</a> 喵！</p>
			</div>
			<?php
		}
	}

	public function activate() {
		global $wpdb;

		// 初始化白名单
		$settings = get_option(self::OPTION_NAME);
		if (!$settings) {
			// 获取当前库名 + 系统库名
			$default_allowed = array($wpdb->dbname, 'information_schema', 'performance_schema', 'mysql', 'sys');
			update_option(self::OPTION_NAME, array(
				'email_notify' => 1,
				'allowed_databases' => $default_allowed
			));
		}
		if (!wp_next_scheduled('gg_db_weekly_check_event')) {
			wp_schedule_event(time(), 'weekly', 'gg_db_weekly_check_event');
		}
	}

	public function deactivate() {
		wp_clear_scheduled_hook('gg_db_weekly_check_event');
	}
	public static function uninstall() {
		delete_option(self::OPTION_NAME);
		delete_option(self::RESULT_OPTION_NAME);
	}
}


new GG_DB_Security_Monitor();
