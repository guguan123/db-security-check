<?php
/*
Plugin Name: MySQL Security Monitor
Description: 监控数据库是否有异常
Version: 1.1
Author: GuGuan123's Cat
*/

if (!defined('ABSPATH')) exit;

class GG_DB_Security_Monitor {

	private $option_name = 'gg_db_monitor_settings';

	public function __construct() {
		// 挂载后台提醒
		//add_action('admin_notices', array($this, 'display_admin_alerts'));
		// 挂载菜单
		add_action('admin_menu', array($this, 'create_menu'));
		// 注册 Cron 任务
		add_action('gg_db_weekly_check_event', array($this, 'run_security_check'));
		
		// 激活插件时初始化 Cron
		register_activation_hook(__FILE__, array($this, 'activate'));
		register_deactivation_hook(__FILE__, array($this, 'deactivate'));
	}

	// 核心检测逻辑
	public function run_security_check($is_manual = false) {
		global $wpdb;
		$alerts = [];

		// 检测 --skip-grant-tables
		$result = $wpdb->get_row("SHOW VARIABLES LIKE 'skip_grant_tables'");
		if ($result && strtoupper($result->Value) == 'ON') {
			$alerts[] = "🚨 危险：数据库正处于 --skip-grant-tables 模式运行！";
		}

		// 检测异常数据库
		$databases = $wpdb->get_col("SHOW DATABASES");
		$allowed_db = array('guguan_sql', 'information_schema', 'performance_schema', 'mysql', 'sys');
		$unknown_dbs = array_diff($databases, $allowed_db);

		if (!empty($unknown_dbs)) {
			$alerts[] = "🔍 检测到异常数据库：" . implode(', ', $unknown_dbs);
		}

		// 如果有异常且开启了邮件通知，则发信
		if (!empty($alerts) && !$is_manual) {
			$settings = get_option($this->option_name);
			if (!empty($settings['email_notify'])) {
				$to = get_option('admin_email');
				$subject = '数据库安全预警 - ' . get_bloginfo('name');
				$body = "发现数据库异常：\n\n" . implode("\n", $alerts);
				wp_mail($to, $subject, $body);
			}
		}

		return $alerts;
	}

	// 创建管理页面
	public function create_menu() {
		add_options_page('DB Security', 'DB Security', 'manage_options', 'gg-db-monitor', array($this, 'settings_page'));
	}

	public function settings_page() {
		if (isset($_POST['save_settings'])) {
			$new_settings = array('email_notify' => isset($_POST['email_notify']) ? 1 : 0);
			update_option($this->option_name, $new_settings);
			echo '<div class="updated"><p>设置已保存喵！</p></div>';
		}

		$settings = get_option($this->option_name);
		$alerts = $this->run_security_check(true); // 手动触发一次检测显示在页面上
		?>
		<div class="wrap">
			<h1>MySQL Security Monitor</h1>
			<hr>
			<h3>当前状态：</h3>
			<?php if (empty($alerts)): ?>
				<p style="color: green; font-weight: bold;">数据库无异常</p>
			<?php else: ?>
				<div class="notice notice-error"><p><?php echo implode('<br>', $alerts); ?></p></div>
			<?php endif; ?>

			<form method="post" style="margin-top: 20px;">
				<table class="form-table">
					<tr>
						<th scope="row">邮件预警</th>
						<td>
							<label>
								<input type="checkbox" name="email_notify" <?php checked(1, $settings['email_notify'] ?? 0); ?>>
								发现异常时自动发送邮件给管理员 (<?php echo get_option('admin_email'); ?>)
							</label>
						</td>
					</tr>
					<tr>
						<th scope="row">自动检测</th>
						<td>每周自动进行一次后台静默检测。</td>
					</tr>
				</table>
				<p class="submit"><input type="submit" name="save_settings" class="button button-primary" value="保存设置"></p>
			</form>
		</div>
		<?php
	}

	// 后台顶部提醒
	public function display_admin_alerts() {
		$alerts = $this->run_security_check(true);
		if (!empty($alerts)) {
			echo '<div class="notice notice-error"><p><b>发现数据库异常！</b> 请前往“设置 -> DB Security”查看详情。</p></div>';
		}
	}

	// Cron 任务管理
	public function activate() {
		if (!wp_next_scheduled('gg_db_weekly_check_event')) {
			wp_schedule_event(time(), 'weekly', 'gg_db_weekly_check_event');
		}
	}

	public function deactivate() {
		wp_clear_scheduled_hook('gg_db_weekly_check_event');
	}
}

// 实例化插件
new GG_DB_Security_Monitor();
