<?php
/*
Plugin Name: MySQL Security Monitor
Description: 监控数据库是否有异常
Version: 1.2
Author: GuGuan123's Cat
*/

if (!defined('ABSPATH')) exit;

class GG_DB_Security_Monitor {

	private $option_name = 'gg_db_monitor_settings';

	public function __construct() {
		// 挂载后台顶部提醒（每次加载后台页面时触发）
		//add_action('admin_notices', array($this, 'display_admin_alerts'));
		// 挂载菜单
		add_action('admin_menu', array($this, 'create_menu'));
		// 注册 Cron 任务（自动检测发邮件）
		add_action('gg_db_weekly_check_event', array($this, 'run_security_check'));

		// 激活插件时初始化 Cron
		register_activation_hook(__FILE__, array($this, 'activate'));
		register_deactivation_hook(__FILE__, array($this, 'deactivate'));
	}

	/**
	 * 核心检测逻辑
	 * @param bool $send_mail 是否为 Cron 自动运行（决定是否发邮件）
	 * @return array 检测结果数组
	 */
	public function run_security_check($send_mail = false) {
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

		// 只有 Cron 自动检测时才发送邮件通知
		if (!empty($alerts) && $send_mail) {
			$settings = get_option($this->option_name);
			if (!empty($settings['email_notify'])) {
				$to = get_option('admin_email');
				$subject = get_bloginfo('name') . ' - 检测到数据库异常';
				$body = "系统在自动检测中发现以下数据库异常：" . PHP_EOL;
				foreach ($alerts as $alert) {
					$body .= "• " . strip_tags($alert) . PHP_EOL;
				}
				$body .= PHP_EOL . "请尽快登录后台查看详情：" . admin_url('options-general.php?page=gg-db-monitor') . PHP_EOL;
				$body .= "—— MySQL Security Monitor 自动发送";
				wp_mail($to, $subject, $body);
			}
		}

		return $alerts;
	}

	// 创建管理页面
	public function create_menu() {
		add_options_page('DB Security', 'DB Security', 'manage_options', 'gg-db-monitor', array($this, 'settings_page'));
	}

	/**
	 * 设置页面 - 每次打开都会自动运行检测
	 */
	public function settings_page() {
		// 保存设置
		if (isset($_POST['save_settings'])) {
			$new_settings = array('email_notify' => isset($_POST['email_notify']) ? 1 : 0);
			update_option($this->option_name, $new_settings);
			echo '<div class="updated"><p>设置已保存喵！</p></div>';
		}

		$settings = get_option($this->option_name);

		// 每次打开页面都自动运行检测（手动模式，不发邮件）
		$alerts = $this->run_security_check(false);

		// 显示最后检测时间
		$last_check_time = current_time('mysql');
		?>
		<div class="wrap">
			<h1>🔒 MySQL Security Monitor</h1>
			<p>检测时间：<?php echo $last_check_time; ?> | 状态：<span style="color: <?php echo empty($alerts) ? 'green' : 'red'; ?>; font-weight: bold;"><?php echo empty($alerts) ? '✅ 正常' : '❌ 发现异常'; ?></span></p>
			<hr>

			<h3>检测结果：</h3>
			<?php if (empty($alerts)): ?>
				<div class="notice notice-success" style="background: #d4edda; border-left-color: #28a745;">
					<p><strong>✅ 数据库状态良好</strong></p>
				</div>
			<?php else: ?>
				<div class="notice notice-error">
					<p><strong>⚠️ 发现以下安全问题：</strong></p>
					<ul style="list-style: disc; margin-left: 20px;">
						<?php foreach ($alerts as $alert): ?>
							<li style="margin: 5px 0;"><?php echo esc_html($alert); ?></li>
						<?php endforeach; ?>
					</ul>
				</div>
			<?php endif; ?>

			<form method="post" style="margin-top: 20px; background: #fff; padding: 20px; border: 1px solid #ccd0d4; box-shadow: 0 1px 1px rgba(0,0,0,.04);">
				<h3>⚙️ 设置</h3>
				<table class="form-table">
					<tr>
						<th scope="row">邮件预警</th>
						<td>
							<label>
								<input type="checkbox" name="email_notify" <?php checked(1, $settings['email_notify'] ?? 0); ?>>
								发现异常时自动发送邮件给管理员 (<?php echo get_option('admin_email'); ?>)
							</label>
							<p class="description">仅在 Cron 自动检测时发送邮件，手动查看页面不会触发邮件</p>
						</td>
					</tr>
					<tr>
						<th scope="row">自动检测</th>
						<td>
							<p>每周自动进行一次后台静默检测。</p>
							<p class="description">下次检测时间：<?php 
								$next = wp_next_scheduled('gg_db_weekly_check_event');
								echo $next ? date('Y-m-d H:i:s', $next) : '未安排（请重新激活插件）';
								?></p>
						</td>
					</tr>
				</table>
				<p class="submit"><input type="submit" name="save_settings" class="button button-primary" value="保存设置"></p>
			</form>
		</div>
		<?php
	}

	/**
	 * 后台顶部提醒 - 每次加载后台页面都会检测
	 */
	public function display_admin_alerts() {
		// 只在非设置页面显示提醒（避免重复显示）
		if (isset($_GET['page']) && $_GET['page'] === 'gg-db-monitor') {
			return;
		}

		// 快速检测（不发邮件）
		$alerts = $this->run_security_check(false);

		if (!empty($alerts)) {
			echo '<div class="notice notice-error is-dismissible">';
			echo '<p><strong>🚨 数据库安全警告！</strong> 发现 ' . count($alerts) . ' 个问题，请<a href="' . admin_url('options-general.php?page=gg-db-monitor') . '">立即查看详情</a>。</p>';
			echo '</div>';
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

new GG_DB_Security_Monitor();
